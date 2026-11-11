"""Train only the ETAP adapter on simulator labels, with the LM frozen."""

from __future__ import annotations

import os
from typing import Any, Optional

import torch

from etap_encoder.batch import EtapBatch, EtapSim
from etap_encoder.constants import HIDDEN_SIZE, QWEN35_2B_BASE
from etap_encoder.fake_qwen import FakeQwen, TinyTokenizer
from etap_encoder.labels import TASKS, Task, derive_example
from etap_encoder.model import EtapAdapter, EtapQwenModel


def load_language_model(
    model_id: Optional[str] = None,
    hidden_size: int = HIDDEN_SIZE,
    device: torch.device | str = "cpu",
) -> tuple[Any, Any]:
    """Return (lm, tokenizer). Default is FakeQwen — no weight download.

    Passing Qwen/Qwen3.5-2B-Base (or another transformers id) is supported as a
    hook but requires `transformers` and a local or cached copy of the weights.
    Tests never take this branch.
    """
    if model_id in (None, "", "fake", "FakeQwen"):
        tok = TinyTokenizer()
        lm = FakeQwen(hidden_size=hidden_size, vocab_size=tok.vocab_size)
        return lm.to(device), tok

    # Optional real-model path. Not executed by the test suite.
    try:
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "Installing the real Qwen model needs the `transformers` package, "
            f"then `from_pretrained({model_id!r})`. Tests use FakeQwen instead."
        ) from exc
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.float32,
        trust_remote_code=True,
    )

    class _HfWrap(torch.nn.Module):
        def __init__(self, inner):
            super().__init__()
            self.inner = inner
            self.hidden_size = int(getattr(inner.config, "hidden_size", hidden_size))

        def embed(self, input_ids):
            return self.inner.get_input_embeddings()(input_ids)

        def logits_from_embeds(self, inputs_embeds, attention_mask=None):
            out = self.inner(
                inputs_embeds=inputs_embeds,
                attention_mask=attention_mask,
                use_cache=False,
            )
            return out.logits

        def forward(self, input_ids=None, inputs_embeds=None, attention_mask=None):
            if inputs_embeds is None:
                inputs_embeds = self.embed(input_ids)
            return self.logits_from_embeds(inputs_embeds, attention_mask)

    class _HfTok:
        def __init__(self, tok):
            self.tok = tok
            self.pad_id = tok.pad_token_id if tok.pad_token_id is not None else tok.eos_token_id
            self.bos_id = tok.bos_token_id if tok.bos_token_id is not None else self.pad_id
            self.eos_id = tok.eos_token_id
            self.vocab_size = len(tok)

        def encode(self, text, add_bos=False, add_eos=False):
            ids = self.tok.encode(text, add_special_tokens=False)
            if add_bos and self.bos_id is not None:
                ids = [self.bos_id] + ids
            if add_eos and self.eos_id is not None:
                ids = ids + [self.eos_id]
            return ids

        def batch_encode(self, texts, add_bos=False, add_eos=False, device="cpu"):
            rows = [self.encode(t, add_bos=add_bos, add_eos=add_eos) for t in texts]
            max_len = max((len(r) for r in rows), default=1)
            ids = torch.full((len(rows), max_len), self.pad_id, dtype=torch.long, device=device)
            mask = torch.zeros(len(rows), max_len, dtype=torch.bool, device=device)
            for i, row in enumerate(rows):
                if not row:
                    continue
                ids[i, : len(row)] = torch.tensor(row, dtype=torch.long, device=device)
                mask[i, : len(row)] = True
            return ids, mask

    return _HfWrap(model).to(device), _HfTok(tokenizer)


def _pack_examples(
    batches: list[EtapBatch],
    tokenizer,
    task: Task,
    device: torch.device | str,
):
    examples = [derive_example(b, task=task) for b in batches]
    prefix_ids, prefix_mask = tokenizer.batch_encode(
        [e.prefix for e in examples], add_bos=True, add_eos=False, device=device
    )
    question_ids, question_mask = tokenizer.batch_encode(
        [e.question for e in examples], add_bos=False, add_eos=False, device=device
    )
    answer_ids, answer_mask = tokenizer.batch_encode(
        [e.answer for e in examples], add_bos=False, add_eos=True, device=device
    )
    return {
        "prefix_ids": prefix_ids,
        "prefix_mask": prefix_mask,
        "question_ids": question_ids,
        "question_mask": question_mask,
        "answer_ids": answer_ids,
        "answer_mask": answer_mask,
        "examples": examples,
    }


def train_adapter(
    steps: int = 5,
    lr: float = 1e-3,
    max_records: int = 8,
    lib_path: Optional[os.PathLike] = None,
    model_id: Optional[str] = None,
    device: str = "cpu",
    seed: int = 0,
    task_cycle: tuple[Task, ...] = TASKS,
) -> dict:
    """Run a few adapter-only optimizer steps on etap://sim batches.

    The language model (FakeQwen by default) stays frozen. Real Qwen weights
    are never downloaded unless model_id is an explicit Hugging Face id.
    """
    torch.manual_seed(seed)
    lm, tokenizer = load_language_model(model_id, device=device)
    adapter = EtapAdapter(hidden_size=getattr(lm, "hidden_size", HIDDEN_SIZE)).to(device)
    model = EtapQwenModel(adapter, lm, tokenizer)
    trainable = model.freeze_lm()
    params = [p for p in model.adapter.parameters() if p.requires_grad]
    opt = torch.optim.Adam(params, lr=lr)

    losses: list[float] = []
    answers: list[str] = []
    with EtapSim(lib_path=lib_path, max_records=max_records) as sim:
        for step in range(steps):
            batch = sim.poll()
            if batch is None:
                break
            task = task_cycle[step % len(task_cycle)]
            packed = _pack_examples([batch], tokenizer, task, device)
            opt.zero_grad(set_to_none=True)
            out = model(
                [batch],
                packed["prefix_ids"],
                packed["question_ids"],
                packed["answer_ids"],
                prefix_mask=packed["prefix_mask"],
                question_mask=packed["question_mask"],
                answer_mask=packed["answer_mask"],
                device=device,
            )
            loss = out["loss"]
            if not torch.isfinite(loss):
                raise RuntimeError(f"non-finite loss at step {step}: {loss}")
            loss.backward()
            opt.step()
            losses.append(float(loss.detach().cpu()))
            answers.append(packed["examples"][0].answer)

    return {
        "steps": len(losses),
        "losses": losses,
        "answers": answers,
        "trainable": trainable,
        "model_id": model_id or "fake",
        "hidden_size": int(getattr(lm, "hidden_size", HIDDEN_SIZE)),
    }


# Re-export so the CLI can mention the official id without importing transformers.
REAL_MODEL_ID = QWEN35_2B_BASE
