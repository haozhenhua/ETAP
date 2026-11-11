"""CPU tests for the minimal ETAP adapter. No GPU, no Hugging Face download."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from etap_encoder.batch import EtapSim, ensure_libetap
from etap_encoder.constants import BYTE_PAD, HIDDEN_SIZE, PATCH_SIZE
from etap_encoder.fake_qwen import FakeQwen, TinyTokenizer
from etap_encoder.features import bytes_to_patches, encode_batches
from etap_encoder.labels import derive_example
from etap_encoder.model import EtapAdapter, EtapQwenModel
from etap_encoder.train import _pack_examples


def _one_batch(max_records: int = 8):
    ensure_libetap()
    with EtapSim(max_records=max_records) as sim:
        batch = sim.poll()
    if batch is None:
        raise RuntimeError("etap://sim returned EMPTY on the first poll")
    return batch


class TestAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.batch = _one_batch()

    def test_sim_batch_has_three_views_and_raw_bytes(self):
        b = self.batch
        self.assertGreater(b.packet.n, 0)
        self.assertGreater(b.parse.n, 0)
        self.assertGreater(b.flow.n, 0)
        self.assertEqual(len(b.packet.packet_bytes), b.packet.n)
        raw = b.packet.packet_bytes[0]
        self.assertIsInstance(raw, np.ndarray)
        self.assertEqual(raw.dtype, np.uint8)
        self.assertGreater(raw.size, 0)
        # EtherType IPv4 lives in the captured bytes; this is not a text dump.
        if raw.size >= 14:
            self.assertEqual(int(raw[12]), 0x08)
            self.assertEqual(int(raw[13]), 0x00)
        # At least one parse field should be present on the simulator path.
        self.assertTrue(b.parse.valid["tcp_dport"].any())

    def test_adapter_output_shape_and_mask(self):
        b = self.batch
        adapter = EtapAdapter(hidden_size=HIDDEN_SIZE)
        adapter.eval()
        with torch.no_grad():
            tokens, mask = adapter([b], device="cpu")
        expected_t = b.flow.n + b.packet.n + b.parse.n
        self.assertEqual(tokens.shape[0], 1)
        self.assertEqual(tokens.shape[2], HIDDEN_SIZE)
        self.assertEqual(tokens.shape[1], mask.shape[1])
        self.assertEqual(int(mask.sum().item()), expected_t)
        self.assertTrue(torch.isfinite(tokens).all())

    def test_data_path_is_embeddings_not_strings(self):
        b = self.batch
        # Packet bytes enter the adapter as integer tensors, not hex/JSON text.
        patches, pmask = bytes_to_patches(b.packet.packet_bytes)
        self.assertEqual(patches.dtype, np.int64)
        self.assertEqual(patches.shape[-1], PATCH_SIZE)
        raw = b.packet.packet_bytes[0]
        # The first patch must reproduce the captured bytes, including non-text
        # values such as 0x08 (EtherType high byte) — a hex dump would be ASCII.
        first = patches[0, 0]
        n = min(len(raw), PATCH_SIZE)
        np.testing.assert_array_equal(first[:n], raw[:n].astype(np.int64))
        if n < PATCH_SIZE:
            self.assertTrue(np.all(first[n:] == BYTE_PAD))
        self.assertTrue(pmask[0, 0])

        inp = encode_batches([b], device="cpu")
        self.assertEqual(inp.pkt_bytes.dtype, torch.int64)
        self.assertEqual(tuple(inp.pkt_bytes[0, 0, 0, :n].tolist()), tuple(int(x) for x in raw[:n]))

        tok = TinyTokenizer()
        lm = FakeQwen(hidden_size=HIDDEN_SIZE, vocab_size=tok.vocab_size)
        model = EtapQwenModel(EtapAdapter(), lm, tok)
        model.freeze_lm()
        packed = _pack_examples([b], tok, "protocol", "cpu")
        seen = {}

        def hook(inputs_embeds, attention_mask=None):
            seen["inputs_embeds"] = inputs_embeds
            seen["attention_mask"] = attention_mask
            return lm.__class__.logits_from_embeds(lm, inputs_embeds, attention_mask)

        lm.logits_from_embeds = hook  # type: ignore[method-assign]
        out = model(
            [b],
            packed["prefix_ids"],
            packed["question_ids"],
            packed["answer_ids"],
            prefix_mask=packed["prefix_mask"],
            question_mask=packed["question_mask"],
            answer_mask=packed["answer_mask"],
            device="cpu",
        )
        self.assertIn("inputs_embeds", seen)
        self.assertEqual(seen["inputs_embeds"].dim(), 3)
        self.assertEqual(seen["inputs_embeds"].shape[-1], HIDDEN_SIZE)
        self.assertIs(out["inputs_embeds"], seen["inputs_embeds"])
        # The tokenizer never sees packet bytes: its vocab has no hex payload,
        # and adapter tokens have no corresponding input_ids.
        adapter_len = int(out["adapter_mask"].shape[1])
        self.assertGreater(adapter_len, 0)
        total = out["inputs_embeds"].shape[1]
        text_len = packed["prefix_ids"].shape[1] + packed["question_ids"].shape[1] + packed["answer_ids"].shape[1]
        self.assertEqual(total, text_len + adapter_len)

    def test_freeze_lm_only_adapter_trainable(self):
        tok = TinyTokenizer()
        lm = FakeQwen(hidden_size=HIDDEN_SIZE, vocab_size=tok.vocab_size)
        model = EtapQwenModel(EtapAdapter(), lm, tok)
        names = model.freeze_lm()
        self.assertTrue(names)
        for n, p in model.named_parameters():
            if n.startswith("adapter."):
                self.assertTrue(p.requires_grad, n)
                self.assertIn(n, names)
            else:
                self.assertFalse(p.requires_grad, n)
                self.assertTrue(n.startswith("lm."), n)
        self.assertTrue(all(n.startswith("adapter.") for n in names))
        self.assertFalse(any("embed_tokens" in n or "lm_head" in n for n in names))

    def test_one_step_freezes_lm_and_updates_adapter(self):
        torch.manual_seed(0)
        b = self.batch
        tok = TinyTokenizer()
        lm = FakeQwen(hidden_size=HIDDEN_SIZE, vocab_size=tok.vocab_size)
        adapter = EtapAdapter()
        model = EtapQwenModel(adapter, lm, tok)
        model.freeze_lm()

        lm_before = {n: p.detach().clone() for n, p in model.lm.named_parameters()}
        ad_before = {n: p.detach().clone() for n, p in model.adapter.named_parameters()}

        packed = _pack_examples([b], tok, "protocol", "cpu")
        opt = torch.optim.Adam([p for p in model.adapter.parameters() if p.requires_grad], lr=1e-2)
        opt.zero_grad(set_to_none=True)
        out = model(
            [b],
            packed["prefix_ids"],
            packed["question_ids"],
            packed["answer_ids"],
            prefix_mask=packed["prefix_mask"],
            question_mask=packed["question_mask"],
            answer_mask=packed["answer_mask"],
            device="cpu",
        )
        loss = out["loss"]
        self.assertTrue(torch.isfinite(loss), f"loss={loss}")
        loss.backward()
        opt.step()

        for n, p in model.lm.named_parameters():
            self.assertTrue(torch.equal(p.detach(), lm_before[n]), f"LM changed: {n}")
        changed = 0
        for n, p in model.adapter.named_parameters():
            if not torch.equal(p.detach(), ad_before[n]):
                changed += 1
        self.assertGreater(changed, 0, "expected at least one adapter parameter to change")

    def test_labels_are_simulator_derived(self):
        ex = derive_example(self.batch, task="protocol")
        self.assertIn(ex.answer, {"http", "tls", "ipv4", "tcp", "eth", "unknown"})
        ex2 = derive_example(self.batch, task="dport")
        self.assertIn(ex2.answer, {"http", "https", "other"})
        ex3 = derive_example(self.batch, task="event")
        self.assertIn(ex3.answer, {"new", "update", "expire", "reset", "anomaly", "unknown"})


if __name__ == "__main__":
    unittest.main()
