"""Convert copied ETAP columns into padded tensors for the three view encoders."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

import numpy as np
import torch

from etap_encoder.batch import EtapBatch
from etap_encoder.constants import BYTE_PAD, MAX_PATCHES, PATCH_SIZE


def bytes_to_patches(
    blobs: Sequence[np.ndarray],
    max_patches: int = MAX_PATCHES,
    patch_size: int = PATCH_SIZE,
) -> tuple[np.ndarray, np.ndarray]:
    """Pack raw uint8 slices into (N, max_patches, patch_size) with a patch mask.

    Padding uses BYTE_PAD (256), which is outside the 0..255 byte range, so the
    model never confuses pad with a real 0x00 byte. This path is purely tensor
    based: it does not hex-encode or stringify the bytes.
    """
    n = len(blobs)
    patches = np.full((n, max_patches, patch_size), BYTE_PAD, dtype=np.int64)
    mask = np.zeros((n, max_patches), dtype=np.bool_)
    cap = max_patches * patch_size
    for i, raw in enumerate(blobs):
        if raw is None or len(raw) == 0:
            continue
        data = np.asarray(raw, dtype=np.uint8)
        if data.size > cap:
            data = data[:cap]
        n_patches = (data.size + patch_size - 1) // patch_size
        padded = np.full(n_patches * patch_size, BYTE_PAD, dtype=np.int64)
        padded[: data.size] = data.astype(np.int64)
        patches[i, :n_patches] = padded.reshape(n_patches, patch_size)
        mask[i, :n_patches] = True
        # bytes past the real length in the last patch stay BYTE_PAD
        rem = data.size % patch_size
        if rem:
            patches[i, n_patches - 1, rem:] = BYTE_PAD
    return patches, mask


def _log1p(x: np.ndarray) -> np.ndarray:
    return np.log1p(np.asarray(x, dtype=np.float64)).astype(np.float32)


def _f32(x: np.ndarray) -> np.ndarray:
    return np.asarray(x, dtype=np.float32)



@dataclass
class AdapterInputs:
    """Padded tensors for a batch of ETAP observations (B along the first dim)."""

    pkt_numeric: torch.Tensor  # (B, P, 9)
    pkt_valid: torch.Tensor  # (B, P)
    pkt_bytes: torch.Tensor  # (B, P, max_patches, 16) int64
    pkt_patch_mask: torch.Tensor  # (B, P, max_patches)

    parse_proto: torch.Tensor  # (B, R)
    parse_valid: torch.Tensor
    ipv4_src: torch.Tensor  # (B, R, 4)
    ipv4_dst: torch.Tensor
    ipv4_src_valid: torch.Tensor
    ipv4_dst_valid: torch.Tensor
    sport: torch.Tensor  # (B, R) scaled 0..1
    dport: torch.Tensor
    sport_valid: torch.Tensor
    dport_valid: torch.Tensor
    sni_bytes: torch.Tensor
    sni_mask: torch.Tensor
    host_bytes: torch.Tensor
    host_mask: torch.Tensor

    flow_event: torch.Tensor  # (B, F)
    flow_state: torch.Tensor
    flow_numeric: torch.Tensor  # (B, F, 5)
    flow_valid: torch.Tensor

    def to(self, device: torch.device | str) -> "AdapterInputs":
        kwargs = {k: v.to(device) if torch.is_tensor(v) else v for k, v in self.__dict__.items()}
        return AdapterInputs(**kwargs)


def _packet_numeric(batch: EtapBatch) -> np.ndarray:
    p = batch.packet
    n = p.n
    if n == 0:
        return np.zeros((0, 9), dtype=np.float32)
    first = batch.time_first_ns if batch.time_first_ns else (int(p.ts_ns.min()) if n else 0)
    rel_ms = np.zeros(n, dtype=np.float32)
    if p.valid["ts_ns"].any():
        ts = p.ts_ns.astype(np.float64)
        rel_ms = np.maximum(ts - float(first), 0.0).astype(np.float32) / 1e6
        rel_ms = np.where(p.valid["ts_ns"], rel_ms, 0.0).astype(np.float32)
    feats = np.stack(
        [
            np.where(p.valid["wire_len"], _log1p(p.wire_len), 0.0),
            np.where(p.valid["cap_len"], _log1p(p.cap_len), 0.0),
            np.where(p.valid["bytes_len"], _log1p(p.bytes_len), 0.0),
            np.where(p.valid["dir"], _f32(p.dir), 0.0),
            np.where(p.valid["ifindex"], _log1p(p.ifindex), 0.0),
            np.where(p.valid["flags"], _f32(p.flags) / 255.0, 0.0),
            np.where(p.valid["l3_off"], _f32(p.l3_off) / 64.0, 0.0),
            np.where(p.valid["l4_off"], _f32(p.l4_off) / 64.0, 0.0),
            rel_ms,
        ],
        axis=-1,
    ).astype(np.float32)
    return feats


def _flow_numeric(batch: EtapBatch) -> np.ndarray:
    f = batch.flow
    n = f.n
    if n == 0:
        return np.zeros((0, 5), dtype=np.float32)
    return np.stack(
        [
            np.where(f.valid["pkts_fwd"], _log1p(f.pkts_fwd), 0.0),
            np.where(f.valid["pkts_rev"], _log1p(f.pkts_rev), 0.0),
            np.where(f.valid["bytes_fwd"], _log1p(f.bytes_fwd), 0.0),
            np.where(f.valid["bytes_rev"], _log1p(f.bytes_rev), 0.0),
            np.where(f.valid["duration"], _log1p(f.duration), 0.0),
        ],
        axis=-1,
    ).astype(np.float32)


def encode_batches(batches: Sequence[EtapBatch], device: torch.device | str = "cpu") -> AdapterInputs:
    """Collate one or more EtapBatch objects into padded adapter inputs."""
    if not batches:
        raise ValueError("encode_batches requires at least one batch")
    bsz = len(batches)
    max_p = max(b.packet.n for b in batches)
    max_r = max(b.parse.n for b in batches)
    max_f = max(b.flow.n for b in batches)
    # Keep a minimum of 1 so encoders always receive a well-defined shape.
    max_p = max(max_p, 1)
    max_r = max(max_r, 1)
    max_f = max(max_f, 1)

    pkt_numeric = np.zeros((bsz, max_p, 9), dtype=np.float32)
    pkt_valid = np.zeros((bsz, max_p), dtype=np.bool_)
    pkt_bytes = np.full((bsz, max_p, MAX_PATCHES, PATCH_SIZE), BYTE_PAD, dtype=np.int64)
    pkt_patch_mask = np.zeros((bsz, max_p, MAX_PATCHES), dtype=np.bool_)

    parse_proto = np.zeros((bsz, max_r), dtype=np.int64)
    parse_valid = np.zeros((bsz, max_r), dtype=np.bool_)
    ipv4_src = np.zeros((bsz, max_r, 4), dtype=np.int64)
    ipv4_dst = np.zeros((bsz, max_r, 4), dtype=np.int64)
    ipv4_src_valid = np.zeros((bsz, max_r), dtype=np.bool_)
    ipv4_dst_valid = np.zeros((bsz, max_r), dtype=np.bool_)
    sport = np.zeros((bsz, max_r), dtype=np.float32)
    dport = np.zeros((bsz, max_r), dtype=np.float32)
    sport_valid = np.zeros((bsz, max_r), dtype=np.bool_)
    dport_valid = np.zeros((bsz, max_r), dtype=np.bool_)
    sni_bytes = np.full((bsz, max_r, MAX_PATCHES, PATCH_SIZE), BYTE_PAD, dtype=np.int64)
    sni_mask = np.zeros((bsz, max_r, MAX_PATCHES), dtype=np.bool_)
    host_bytes = np.full((bsz, max_r, MAX_PATCHES, PATCH_SIZE), BYTE_PAD, dtype=np.int64)
    host_mask = np.zeros((bsz, max_r, MAX_PATCHES), dtype=np.bool_)

    flow_event = np.zeros((bsz, max_f), dtype=np.int64)
    flow_state = np.zeros((bsz, max_f), dtype=np.int64)
    flow_numeric = np.zeros((bsz, max_f, 5), dtype=np.float32)
    flow_valid = np.zeros((bsz, max_f), dtype=np.bool_)

    for i, batch in enumerate(batches):
        p, r, f = batch.packet, batch.parse, batch.flow
        if p.n:
            pkt_numeric[i, : p.n] = _packet_numeric(batch)
            pkt_valid[i, : p.n] = True
            patches, mask = bytes_to_patches(p.packet_bytes)
            pkt_bytes[i, : p.n] = patches
            pkt_patch_mask[i, : p.n] = mask
        if r.n:
            parse_proto[i, : r.n] = np.clip(r.proto_id, 0, 15).astype(np.int64)
            parse_valid[i, : r.n] = r.valid["index"]
            n4 = min(r.n, r.ipv4_src.shape[0])
            ipv4_src[i, :n4] = r.ipv4_src[:n4]
            ipv4_dst[i, :n4] = r.ipv4_dst[:n4]
            ipv4_src_valid[i, :n4] = r.valid["ipv4_src"][:n4]
            ipv4_dst_valid[i, :n4] = r.valid["ipv4_dst"][:n4]
            sport[i, : r.n] = (r.tcp_sport.astype(np.float32) / 65535.0)
            dport[i, : r.n] = (r.tcp_dport.astype(np.float32) / 65535.0)
            sport_valid[i, : r.n] = r.valid["tcp_sport"]
            dport_valid[i, : r.n] = r.valid["tcp_dport"]
            sp, sm = bytes_to_patches(r.tls_sni)
            # Only keep patches for rows the validity bitmap marks present.
            sm = sm & r.valid["tls_sni"][:, None]
            sni_bytes[i, : r.n] = sp
            sni_mask[i, : r.n] = sm
            hp, hm = bytes_to_patches(r.http_host)
            hm = hm & r.valid["http_host"][:, None]
            host_bytes[i, : r.n] = hp
            host_mask[i, : r.n] = hm
        if f.n:
            flow_event[i, : f.n] = np.clip(f.event, 0, 31).astype(np.int64)
            flow_state[i, : f.n] = np.clip(f.state, 0, 255).astype(np.int64)
            flow_numeric[i, : f.n] = _flow_numeric(batch)
            flow_valid[i, : f.n] = f.valid["meta"]

    def t(a, dtype=None):
        ten = torch.from_numpy(a)
        if dtype is not None:
            ten = ten.to(dtype)
        return ten.to(device)

    return AdapterInputs(
        pkt_numeric=t(pkt_numeric),
        pkt_valid=t(pkt_valid),
        pkt_bytes=t(pkt_bytes, torch.long),
        pkt_patch_mask=t(pkt_patch_mask),
        parse_proto=t(parse_proto, torch.long),
        parse_valid=t(parse_valid),
        ipv4_src=t(ipv4_src, torch.long),
        ipv4_dst=t(ipv4_dst, torch.long),
        ipv4_src_valid=t(ipv4_src_valid),
        ipv4_dst_valid=t(ipv4_dst_valid),
        sport=t(sport),
        dport=t(dport),
        sport_valid=t(sport_valid),
        dport_valid=t(dport_valid),
        sni_bytes=t(sni_bytes, torch.long),
        sni_mask=t(sni_mask),
        host_bytes=t(host_bytes, torch.long),
        host_mask=t(host_mask),
        flow_event=t(flow_event, torch.long),
        flow_state=t(flow_state, torch.long),
        flow_numeric=t(flow_numeric),
        flow_valid=t(flow_valid),
    )
