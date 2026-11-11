"""Tiny causal stand-in for Qwen3.5-2B-Base (hidden_size=2048, no weight download)."""

from __future__ import annotations

import re
from typing import Optional

import torch
import torch.nn as nn

from etap_encoder.constants import HIDDEN_SIZE
from etap_encoder.model import RMSNorm


# Closed vocabulary for the short prefix / question / answer strings used in tests.
VOCAB = [
    "<pad>",
    "<unk>",
    "<bos>",
    "<eos>",
    "ETAP",
    "traffic",
    ".",
    "protocol",
    "dport",
    "event",
    "?",
    "http",
    "https",
    "tls",
    "ipv4",
    "tcp",
    "eth",
    "unknown",
    "other",
    "new",
    "update",
    "expire",
    "reset",
    "anomaly",
]

_TOKEN_RE = re.compile(r"ETAP|[A-Za-z0-9]+|[.?]")


class TinyTokenizer:
    pad_token = "<pad>"
    unk_token = "<unk>"
    bos_token = "<bos>"
    eos_token = "<eos>"

    def __init__(self, vocab: Optional[list[str]] = None):
        self.vocab = list(vocab or VOCAB)
        self.stoi = {t: i for i, t in enumerate(self.vocab)}
        self.itos = list(self.vocab)
        self.pad_id = self.stoi[self.pad_token]
        self.unk_id = self.stoi[self.unk_token]
        self.bos_id = self.stoi[self.bos_token]
        self.eos_id = self.stoi[self.eos_token]
        self.vocab_size = len(self.vocab)

    def tokenize(self, text: str) -> list[str]:
        return _TOKEN_RE.findall(text)

    def encode(self, text: str, add_bos: bool = False, add_eos: bool = False) -> list[int]:
        ids = [self.stoi.get(t, self.unk_id) for t in self.tokenize(text)]
        if add_bos:
            ids = [self.bos_id] + ids
        if add_eos:
            ids = ids + [self.eos_id]
        return ids

    def decode(self, ids: list[int]) -> str:
        toks = [self.itos[i] if 0 <= i < len(self.itos) else self.unk_token for i in ids]
        toks = [t for t in toks if t not in {self.pad_token, self.bos_token, self.eos_token}]
        out = []
        for t in toks:
            if t in {".", "?"} or not out:
                out.append(t)
            else:
                out.append(" " + t)
        return "".join(out)

    def batch_encode(
        self,
        texts: list[str],
        add_bos: bool = False,
        add_eos: bool = False,
        device: torch.device | str = "cpu",
    ) -> tuple[torch.Tensor, torch.Tensor]:
        encoded = [self.encode(t, add_bos=add_bos, add_eos=add_eos) for t in texts]
        max_len = max((len(x) for x in encoded), default=0)
        max_len = max(max_len, 1)
        ids = torch.full((len(texts), max_len), self.pad_id, dtype=torch.long, device=device)
        mask = torch.zeros(len(texts), max_len, dtype=torch.bool, device=device)
        for i, row in enumerate(encoded):
            if not row:
                continue
            ids[i, : len(row)] = torch.tensor(row, dtype=torch.long, device=device)
            mask[i, : len(row)] = True
        return ids, mask


class TinyCausalBlock(nn.Module):
    """One-layer causal self-attention + MLP so answer positions see adapter tokens."""

    def __init__(self, hidden_size: int, n_heads: int = 4):
        super().__init__()
        if hidden_size % n_heads != 0:
            raise ValueError("hidden_size must be divisible by n_heads")
        self.n_heads = n_heads
        self.head_dim = hidden_size // n_heads
        self.attn_norm = RMSNorm(hidden_size)
        self.qkv = nn.Linear(hidden_size, 3 * hidden_size, bias=False)
        self.proj = nn.Linear(hidden_size, hidden_size, bias=False)
        self.mlp_norm = RMSNorm(hidden_size)
        self.mlp = nn.Sequential(
            nn.Linear(hidden_size, hidden_size),
            nn.GELU(),
            nn.Linear(hidden_size, hidden_size),
        )

    def forward(self, x: torch.Tensor, attention_mask: Optional[torch.Tensor]) -> torch.Tensor:
        b, s, h = x.shape
        xn = self.attn_norm(x)
        qkv = self.qkv(xn).view(b, s, 3, self.n_heads, self.head_dim)
        q, k, v = qkv.unbind(dim=2)
        q = q.transpose(1, 2)
        k = k.transpose(1, 2)
        v = v.transpose(1, 2)
        scale = self.head_dim ** -0.5
        scores = torch.matmul(q, k.transpose(-2, -1)) * scale
        causal = torch.triu(torch.ones(s, s, dtype=torch.bool, device=x.device), diagonal=1)
        fill = torch.zeros(s, s, dtype=torch.bool, device=x.device)
        fill = fill | causal
        if attention_mask is not None:
            key_pad = attention_mask[:, None, None, :] == 0
            fill = fill | key_pad
        scores = scores.masked_fill(fill, torch.finfo(scores.dtype).min)
        attn = torch.softmax(scores, dim=-1)
        attn = torch.nan_to_num(attn, nan=0.0)
        ctx = torch.matmul(attn, v).transpose(1, 2).contiguous().view(b, s, h)
        x = x + self.proj(ctx)
        x = x + self.mlp(self.mlp_norm(x))
        return x


class FakeQwen(nn.Module):
    """Frozen-capable causal stand-in: hidden_size=2048, tiny vocab, 1 layer."""

    def __init__(
        self,
        hidden_size: int = HIDDEN_SIZE,
        vocab_size: Optional[int] = None,
        n_heads: int = 4,
    ):
        super().__init__()
        vocab_size = vocab_size or len(VOCAB)
        self.hidden_size = hidden_size
        self.vocab_size = vocab_size
        self.embed_tokens = nn.Embedding(vocab_size, hidden_size, padding_idx=0)
        self.block = TinyCausalBlock(hidden_size, n_heads=n_heads)
        self.final_norm = RMSNorm(hidden_size)
        self.lm_head = nn.Linear(hidden_size, vocab_size, bias=False)

    def embed(self, input_ids: torch.Tensor) -> torch.Tensor:
        return self.embed_tokens(input_ids)

    def logits_from_embeds(
        self,
        inputs_embeds: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        hidden = self.block(inputs_embeds, attention_mask)
        hidden = self.final_norm(hidden)
        return self.lm_head(hidden)

    def forward(
        self,
        input_ids: Optional[torch.Tensor] = None,
        inputs_embeds: Optional[torch.Tensor] = None,
        attention_mask: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        if inputs_embeds is None:
            if input_ids is None:
                raise ValueError("FakeQwen requires input_ids or inputs_embeds")
            inputs_embeds = self.embed(input_ids)
        return self.logits_from_embeds(inputs_embeds, attention_mask)
