"""Three-view ETAP adapter and frozen-LLM stitcher (inputs_embeds, no new tokens)."""

from __future__ import annotations

from typing import Any, Optional, Sequence

import torch
import torch.nn as nn
import torch.nn.functional as F

from etap_encoder.batch import EtapBatch
from etap_encoder.constants import (
    ADAPTER_DIM,
    BYTE_DIM,
    BYTE_PAD,
    BYTE_VOCAB,
    EVENT_VOCAB,
    HIDDEN_SIZE,
    PROTO_VOCAB,
    STATE_VOCAB,
    VIEW_FLOW,
    VIEW_PACKET,
    VIEW_PARSE,
)
from etap_encoder.features import AdapterInputs, encode_batches


class RMSNorm(nn.Module):
    def __init__(self, dim: int, eps: float = 1e-6):
        super().__init__()
        self.weight = nn.Parameter(torch.ones(dim))
        self.eps = eps

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        orig = x.dtype
        x = x.float()
        rms = x.pow(2).mean(dim=-1, keepdim=True).add(self.eps).rsqrt()
        return (x * rms * self.weight).to(orig)


class BytePatchEncoder(nn.Module):
    """Embed 16-byte patches and mean-pool them. Bytes stay integer tensors."""

    def __init__(self, dim: int = BYTE_DIM):
        super().__init__()
        self.embed = nn.Embedding(BYTE_VOCAB, dim, padding_idx=BYTE_PAD)

    def forward(self, patches: torch.Tensor, patch_mask: torch.Tensor) -> torch.Tensor:
        # patches: (..., max_patches, 16)  mask: (..., max_patches)
        emb = self.embed(patches.clamp(0, BYTE_PAD))  # (..., P, 16, D)
        # Mean over the 16 byte positions, ignoring BYTE_PAD.
        not_pad = (patches != BYTE_PAD).unsqueeze(-1).to(emb.dtype)
        byte_den = not_pad.sum(dim=-2).clamp(min=1.0)
        patch_vec = (emb * not_pad).sum(dim=-2) / byte_den  # (..., P, D)
        mask = patch_mask.unsqueeze(-1).to(emb.dtype)
        den = mask.sum(dim=-2).clamp(min=1.0)
        pooled = (patch_vec * mask).sum(dim=-2) / den  # (..., D)
        pooled = pooled * (mask.sum(dim=-2) > 0).to(pooled.dtype)
        return pooled


class PacketEncoder(nn.Module):
    def __init__(self, d_model: int = ADAPTER_DIM):
        super().__init__()
        self.numeric = nn.Linear(9, d_model)
        self.bytes = BytePatchEncoder()
        self.byte_proj = nn.Linear(BYTE_DIM, d_model)
        self.fuse = nn.Linear(2 * d_model, d_model)

    def forward(self, inp: AdapterInputs) -> torch.Tensor:
        num = self.numeric(inp.pkt_numeric)
        byt = self.byte_proj(self.bytes(inp.pkt_bytes, inp.pkt_patch_mask))
        return self.fuse(torch.cat([num, byt], dim=-1))


class ParseEncoder(nn.Module):
    def __init__(self, d_model: int = ADAPTER_DIM):
        super().__init__()
        self.proto = nn.Embedding(PROTO_VOCAB, d_model, padding_idx=0)
        self.ipv4 = BytePatchEncoder()
        # IPv4 is 4 bytes, not a 16-byte patch; reuse the byte table via a wide pad.
        self.ipv4_proj = nn.Linear(BYTE_DIM, d_model)
        self.port = nn.Linear(2, d_model)
        self.sni = BytePatchEncoder()
        self.host = BytePatchEncoder()
        self.varlen_proj = nn.Linear(BYTE_DIM, d_model)
        self.fuse = nn.Linear(5 * d_model, d_model)

    def _ipv4_token(self, addr: torch.Tensor, valid: torch.Tensor) -> torch.Tensor:
        # addr: (B, R, 4) -> fake a single 16-wide patch with 12 pads
        pad = torch.full(
            addr.shape[:-1] + (12,),
            BYTE_PAD,
            dtype=addr.dtype,
            device=addr.device,
        )
        patch = torch.cat([addr, pad], dim=-1).unsqueeze(-2)  # (B, R, 1, 16)
        mask = valid.unsqueeze(-1)
        return self.ipv4_proj(self.ipv4(patch, mask))

    def forward(self, inp: AdapterInputs) -> torch.Tensor:
        proto = self.proto(inp.parse_proto.clamp(0, PROTO_VOCAB - 1))
        src = self._ipv4_token(inp.ipv4_src, inp.ipv4_src_valid)
        dst = self._ipv4_token(inp.ipv4_dst, inp.ipv4_dst_valid)
        ports = torch.stack([inp.sport, inp.dport], dim=-1)
        port_tok = self.port(ports)
        port_tok = port_tok * (inp.sport_valid | inp.dport_valid).unsqueeze(-1).to(port_tok.dtype)
        sni = self.varlen_proj(self.sni(inp.sni_bytes, inp.sni_mask))
        host = self.varlen_proj(self.host(inp.host_bytes, inp.host_mask))
        return self.fuse(torch.cat([proto, src, dst, port_tok, sni + host], dim=-1))


class FlowEncoder(nn.Module):
    def __init__(self, d_model: int = ADAPTER_DIM):
        super().__init__()
        self.event = nn.Embedding(EVENT_VOCAB, d_model, padding_idx=0)
        self.state = nn.Embedding(STATE_VOCAB, d_model, padding_idx=0)
        self.numeric = nn.Linear(5, d_model)
        self.fuse = nn.Linear(3 * d_model, d_model)

    def forward(self, inp: AdapterInputs) -> torch.Tensor:
        ev = self.event(inp.flow_event.clamp(0, EVENT_VOCAB - 1))
        st = self.state(inp.flow_state.clamp(0, STATE_VOCAB - 1))
        num = self.numeric(inp.flow_numeric)
        return self.fuse(torch.cat([ev, st, num], dim=-1))


class EtapAdapter(nn.Module):
    """Encode flow → packet → parse tokens and project to hidden_size=2048."""

    def __init__(self, hidden_size: int = HIDDEN_SIZE, d_model: int = ADAPTER_DIM):
        super().__init__()
        self.hidden_size = hidden_size
        self.packet = PacketEncoder(d_model)
        self.parse = ParseEncoder(d_model)
        self.flow = FlowEncoder(d_model)
        self.view_type = nn.Embedding(3, d_model)
        self.proj = nn.Sequential(
            nn.Linear(d_model, 4 * d_model),
            nn.GELU(),
            nn.Linear(4 * d_model, hidden_size),
        )
        self.out_norm = RMSNorm(hidden_size)

    def forward(
        self,
        batches: Sequence[EtapBatch] | AdapterInputs,
        device: Optional[torch.device | str] = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        if isinstance(batches, AdapterInputs):
            inp = batches if device is None else batches.to(device)
        else:
            inp = encode_batches(batches, device=device or "cpu")

        flow_h = self.flow(inp) + self.view_type.weight[VIEW_FLOW]
        pkt_h = self.packet(inp) + self.view_type.weight[VIEW_PACKET]
        parse_h = self.parse(inp) + self.view_type.weight[VIEW_PARSE]

        parts = [flow_h, pkt_h, parse_h]
        masks = [inp.flow_valid, inp.pkt_valid, inp.parse_valid]
        tokens = torch.cat(parts, dim=1)
        mask = torch.cat(masks, dim=1)
        projected = self.out_norm(self.proj(tokens))
        projected = projected * mask.unsqueeze(-1).to(projected.dtype)
        return projected, mask


class EtapQwenModel(nn.Module):
    """Stitch adapter tokens into a frozen LM with inputs_embeds.

    Sequence: prefix | adapter (flow→packet→parse) | question | answer
    Loss is cross-entropy on answer tokens only (other positions are -100).
    """

    def __init__(self, adapter: EtapAdapter, lm: Any, tokenizer: Any):
        super().__init__()
        self.adapter = adapter
        self.lm = lm
        self.tokenizer = tokenizer

    def freeze_lm(self) -> list[str]:
        for p in self.lm.parameters():
            p.requires_grad = False
        for p in self.adapter.parameters():
            p.requires_grad = True
        return self.trainable_parameter_names()

    def trainable_parameter_names(self) -> list[str]:
        return [n for n, p in self.named_parameters() if p.requires_grad]

    def _embed(self, input_ids: torch.Tensor) -> torch.Tensor:
        if hasattr(self.lm, "embed"):
            return self.lm.embed(input_ids)
        if hasattr(self.lm, "embed_tokens"):
            return self.lm.embed_tokens(input_ids)
        raise AttributeError("language model has no embed() or embed_tokens")

    def _logits(self, inputs_embeds: torch.Tensor, attention_mask: torch.Tensor) -> torch.Tensor:
        if hasattr(self.lm, "logits_from_embeds"):
            return self.lm.logits_from_embeds(inputs_embeds, attention_mask)
        out = self.lm(inputs_embeds=inputs_embeds, attention_mask=attention_mask)
        return out.logits if hasattr(out, "logits") else out

    def stitch(
        self,
        batches: Sequence[EtapBatch],
        prefix_ids: torch.Tensor,
        question_ids: torch.Tensor,
        answer_ids: torch.Tensor,
        prefix_mask: Optional[torch.Tensor] = None,
        question_mask: Optional[torch.Tensor] = None,
        answer_mask: Optional[torch.Tensor] = None,
        device: Optional[torch.device | str] = None,
    ) -> dict[str, torch.Tensor]:
        device = device or prefix_ids.device
        adapter_tok, adapter_mask = self.adapter(batches, device=device)
        prefix_emb = self._embed(prefix_ids)
        question_emb = self._embed(question_ids)
        answer_emb = self._embed(answer_ids)
        if prefix_mask is None:
            prefix_mask = torch.ones(prefix_ids.shape, dtype=torch.bool, device=device)
        if question_mask is None:
            question_mask = torch.ones(question_ids.shape, dtype=torch.bool, device=device)
        if answer_mask is None:
            answer_mask = torch.ones(answer_ids.shape, dtype=torch.bool, device=device)

        inputs_embeds = torch.cat([prefix_emb, adapter_tok, question_emb, answer_emb], dim=1)
        attention_mask = torch.cat(
            [prefix_mask, adapter_mask, question_mask, answer_mask], dim=1
        ).to(dtype=torch.long)

        labels = torch.full(
            inputs_embeds.shape[:2],
            -100,
            dtype=torch.long,
            device=device,
        )
        # Answer tokens sit at the tail. Pad / masked answer positions stay -100.
        ans_start = prefix_ids.size(1) + adapter_tok.size(1) + question_ids.size(1)
        labels[:, ans_start : ans_start + answer_ids.size(1)] = answer_ids.masked_fill(~answer_mask, -100)
        return {
            "inputs_embeds": inputs_embeds,
            "attention_mask": attention_mask,
            "labels": labels,
            "adapter_mask": adapter_mask,
        }

    def forward(
        self,
        batches: Sequence[EtapBatch],
        prefix_ids: torch.Tensor,
        question_ids: torch.Tensor,
        answer_ids: torch.Tensor,
        prefix_mask: Optional[torch.Tensor] = None,
        question_mask: Optional[torch.Tensor] = None,
        answer_mask: Optional[torch.Tensor] = None,
        device: Optional[torch.device | str] = None,
    ) -> dict[str, torch.Tensor]:
        stitched = self.stitch(
            batches,
            prefix_ids,
            question_ids,
            answer_ids,
            prefix_mask=prefix_mask,
            question_mask=question_mask,
            answer_mask=answer_mask,
            device=device,
        )
        logits = self._logits(stitched["inputs_embeds"], stitched["attention_mask"])
        # Standard causal shift: predict token t from position t-1.
        shift_logits = logits[:, :-1, :].contiguous()
        shift_labels = stitched["labels"][:, 1:].contiguous()
        loss = F.cross_entropy(
            shift_logits.view(-1, shift_logits.size(-1)),
            shift_labels.view(-1),
            ignore_index=-100,
        )
        stitched["logits"] = logits
        stitched["loss"] = loss
        return stitched
