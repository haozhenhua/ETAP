"""ctypes bindings for libetap.so and in-memory columnar batches (not JSON)."""

from __future__ import annotations

import ctypes
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import numpy as np

from etap_encoder import constants as C


# ---------------------------------------------------------------------------
# Packed C layouts (etap.h uses #pragma pack(push, 1))
# ---------------------------------------------------------------------------

class EtapOpenOpt(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("timeout_ms", ctypes.c_uint32), ("flags", ctypes.c_uint32)]


class EtapCapsHdr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("version", ctypes.c_uint16),
        ("hdr_len", ctypes.c_uint16),
        ("flags", ctypes.c_uint32),
        ("port_id", ctypes.c_uint32),
        ("clock", ctypes.c_uint8),
        ("endian", ctypes.c_uint8),
        ("reserved0", ctypes.c_uint16),
        ("max_batch_records", ctypes.c_uint32),
        ("max_batch_bytes", ctypes.c_uint32),
        ("min_wait_us", ctypes.c_uint32),
        ("max_wait_us", ctypes.c_uint32),
        ("max_slice", ctypes.c_uint32),
        ("view_mask", ctypes.c_uint32),
        ("n_protos", ctypes.c_uint16),
        ("n_fields", ctypes.c_uint16),
        ("n_features", ctypes.c_uint16),
        ("reserved1", ctypes.c_uint16),
        ("protos_off", ctypes.c_uint32),
        ("fields_off", ctypes.c_uint32),
        ("features_off", ctypes.c_uint32),
        ("strtab_off", ctypes.c_uint32),
        ("strtab_len", ctypes.c_uint32),
        ("time_res_ns", ctypes.c_uint32),
        ("snaplen_max", ctypes.c_uint32),
    ]


class EtapSubReqHdr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("req_len", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("view_mask", ctypes.c_uint32),
        ("max_records", ctypes.c_uint32),
        ("max_bytes", ctypes.c_uint32),
        ("max_wait_us", ctypes.c_uint32),
        ("budget_rps", ctypes.c_uint32),
        ("budget_bps", ctypes.c_uint64),
        ("overflow", ctypes.c_uint8),
        ("sample_mode", ctypes.c_uint8),
        ("reserved", ctypes.c_uint16),
        ("sample_n", ctypes.c_uint32),
        ("sample_k", ctypes.c_uint32),
        ("filter_off", ctypes.c_uint32),
        ("filter_len", ctypes.c_uint32),
        ("packet_off", ctypes.c_uint32),
        ("parse_off", ctypes.c_uint32),
        ("flow_off", ctypes.c_uint32),
    ]


class EtapPacketSelHdr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("meta_mask", ctypes.c_uint32),
        ("bytes_mode", ctypes.c_uint8),
        ("n_ranges", ctypes.c_uint8),
        ("reserved", ctypes.c_uint16),
        ("max_bytes", ctypes.c_uint16),
    ]


class EtapBatchHdr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("magic", ctypes.c_uint32),
        ("version", ctypes.c_uint16),
        ("hdr_len", ctypes.c_uint16),
        ("flags", ctypes.c_uint32),
        ("n_sections", ctypes.c_uint16),
        ("clock", ctypes.c_uint8),
        ("reserved0", ctypes.c_uint8),
        ("batch_id", ctypes.c_uint64),
        ("sub_id", ctypes.c_uint64),
        ("epoch", ctypes.c_uint32),
        ("schema_id", ctypes.c_uint32),
        ("seq", ctypes.c_uint64),
        ("time_first_ns", ctypes.c_uint64),
        ("time_last_ns", ctypes.c_uint64),
        ("n_packets", ctypes.c_uint32),
        ("n_parse_rows", ctypes.c_uint32),
        ("n_flows", ctypes.c_uint32),
        ("reserved1", ctypes.c_uint32),
        ("gap_dropped_pkts", ctypes.c_uint64),
        ("gap_dropped_bytes", ctypes.c_uint64),
        ("gap_first_pkt_id", ctypes.c_uint64),
        ("gap_last_pkt_id", ctypes.c_uint64),
        ("producer_lag_us", ctypes.c_uint32),
        ("crc32c", ctypes.c_uint32),
        ("sections_off", ctypes.c_uint32),
        ("total_size", ctypes.c_uint32),
    ]


class EtapSection(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("kind", ctypes.c_uint16),
        ("flags", ctypes.c_uint16),
        ("count", ctypes.c_uint32),
        ("off", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
    ]


class EtapSubReq(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("bytes", ctypes.c_void_p), ("len", ctypes.c_uint32)]


# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_lib_path() -> Path:
    env = os.environ.get("ETAP_LIB")
    if env:
        return Path(env)
    return repo_root() / "build" / "libetap.so"


def ensure_libetap(lib_path: Optional[os.PathLike] = None) -> Path:
    path = Path(lib_path) if lib_path else default_lib_path()
    if path.exists():
        return path
    script = repo_root() / "build.sh"
    if not script.exists():
        raise FileNotFoundError(f"libetap.so not found at {path} and no build.sh")
    subprocess.check_call([str(script)], cwd=str(repo_root()))
    if not path.exists():
        raise FileNotFoundError(f"build.sh ran but {path} is still missing")
    return path


def load_lib(lib_path: Optional[os.PathLike] = None) -> ctypes.CDLL:
    path = ensure_libetap(lib_path)
    lib = ctypes.CDLL(str(path))
    lib.etap_open.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.etap_open.restype = ctypes.c_int
    lib.etap_close.argtypes = [ctypes.c_void_p]
    lib.etap_close.restype = ctypes.c_int
    lib.etap_discover.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.etap_discover.restype = ctypes.c_int
    lib.etap_caps_free.argtypes = [ctypes.c_void_p]
    lib.etap_caps_free.restype = None
    lib.etap_caps_header.argtypes = [ctypes.c_void_p]
    lib.etap_caps_header.restype = ctypes.c_void_p
    lib.etap_subscribe.argtypes = [ctypes.c_void_p, ctypes.POINTER(EtapSubReq), ctypes.POINTER(ctypes.c_void_p)]
    lib.etap_subscribe.restype = ctypes.c_int
    lib.etap_unsubscribe.argtypes = [ctypes.c_void_p]
    lib.etap_unsubscribe.restype = ctypes.c_int
    lib.etap_poll.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_void_p)]
    lib.etap_poll.restype = ctypes.c_int
    lib.etap_release.argtypes = [ctypes.c_void_p]
    lib.etap_release.restype = ctypes.c_int
    lib.etap_batch_header.argtypes = [ctypes.c_void_p]
    lib.etap_batch_header.restype = ctypes.c_void_p
    lib.etap_col.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint16,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    lib.etap_col.restype = ctypes.c_int
    lib.etap_batch_data.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    lib.etap_batch_data.restype = ctypes.c_void_p
    lib.etap_parse_index.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    lib.etap_parse_index.restype = ctypes.c_void_p
    lib.etap_flow_meta.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    lib.etap_flow_meta.restype = ctypes.c_void_p
    return lib


def build_full_req(
    view_mask: int = C.ETAP_VIEW_ALL,
    max_records: int = 8,
    meta_mask: int = C.ETAP_META_ALL,
    bytes_mode: int = C.ETAP_BYTES_PREFIX,
    max_pkt_bytes: int = 128,
    fields=C.ALL_PARSE_FIELDS,
    feats=C.ALL_FLOW_FEATS,
    flags: int = 0,
) -> bytes:
    """Subscription request layout matching tests/test_etap.c build_full_req."""
    fields = list(fields or ())
    feats = list(feats or ())
    off = ctypes.sizeof(EtapSubReqHdr)

    pkt = EtapPacketSelHdr()
    pkt.meta_mask = meta_mask
    pkt.bytes_mode = bytes_mode
    pkt.n_ranges = 0
    pkt.reserved = 0
    pkt.max_bytes = max_pkt_bytes
    packet_off = off
    pkt_bytes = bytes(pkt)
    off += len(pkt_bytes)

    parse_off = off
    n_fields = len(fields)
    parse_hdr = (
        (3).to_bytes(2, "little")  # flags
        + (0).to_bytes(2, "little")  # n_protos
        + n_fields.to_bytes(2, "little")
        + (0).to_bytes(2, "little")
    )
    field_bytes = b"".join(int(f).to_bytes(4, "little") for f in fields)
    off += len(parse_hdr) + len(field_bytes)

    flow_off = off
    n_feats = len(feats)
    flow_hdr = (
        (0x1F).to_bytes(2, "little")  # event mask
        + (1).to_bytes(2, "little")  # flags
        + n_feats.to_bytes(2, "little")
        + (0).to_bytes(2, "little")
    )
    feat_bytes = b"".join(int(f).to_bytes(4, "little") for f in feats)
    off += len(flow_hdr) + len(feat_bytes)

    hdr = EtapSubReqHdr()
    ctypes.memset(ctypes.addressof(hdr), 0, ctypes.sizeof(hdr))
    hdr.req_len = off
    hdr.flags = flags
    hdr.view_mask = view_mask
    hdr.max_records = max_records
    hdr.max_bytes = 65536
    hdr.max_wait_us = 0
    hdr.packet_off = packet_off
    hdr.parse_off = parse_off
    hdr.flow_off = flow_off
    return bytes(hdr) + pkt_bytes + parse_hdr + field_bytes + flow_hdr + feat_bytes


# ---------------------------------------------------------------------------
# Column helpers
# ---------------------------------------------------------------------------

def _validity(valid_ptr, n: int) -> np.ndarray:
    mask = np.ones(n, dtype=np.bool_)
    if not valid_ptr or n == 0:
        return mask
    nbytes = (n + 7) // 8
    raw = ctypes.string_at(valid_ptr, nbytes)
    bits = np.frombuffer(raw, dtype=np.uint8)
    idx = np.arange(n)
    mask = ((bits[idx // 8] >> (idx % 8)) & 1).astype(np.bool_)
    return mask


def _copy_fixed(data_ptr, n: int, typ: int) -> np.ndarray:
    if typ == C.ETAP_T_IPV4:
        if n == 0 or not data_ptr:
            return np.zeros((n, 4), dtype=np.uint8)
        raw = np.frombuffer(ctypes.string_at(data_ptr, n * 4), dtype="<u4").copy()
        return np.stack(
            [
                (raw >> 24) & 0xFF,
                (raw >> 16) & 0xFF,
                (raw >> 8) & 0xFF,
                raw & 0xFF,
            ],
            axis=-1,
        ).astype(np.uint8)
    dt = C.NUMPY_DTYPE.get(typ)
    if dt is None:
        return np.zeros(n, dtype=np.uint8)
    width = np.dtype(dt).itemsize
    if typ in (C.ETAP_T_MAC, C.ETAP_T_IPV6):
        width = C.TYPE_WIDTH[typ]
        cols = width
        if n == 0 or not data_ptr:
            return np.zeros((n, cols), dtype=np.uint8)
        buf = ctypes.string_at(data_ptr, n * cols)
        return np.frombuffer(buf, dtype=np.uint8).copy().reshape(n, cols)
    if n == 0 or not data_ptr:
        return np.zeros(n, dtype=dt)
    buf = ctypes.string_at(data_ptr, n * width)
    return np.frombuffer(buf, dtype=dt).copy()


def _copy_varlen(data_ptr, off_ptr, n: int) -> tuple[list[np.ndarray], np.ndarray]:
    empty: list[np.ndarray] = [np.zeros(0, dtype=np.uint8) for _ in range(n)]
    lengths = np.zeros(n, dtype=np.int32)
    if n == 0 or not off_ptr:
        return empty, lengths
    offs = np.frombuffer(ctypes.string_at(off_ptr, 4 * (n + 1)), dtype="<u4").copy()
    heap_len = int(offs[-1])
    heap = b""
    if heap_len and data_ptr:
        heap = ctypes.string_at(data_ptr, heap_len)
    out = []
    for i in range(n):
        a, b = int(offs[i]), int(offs[i + 1])
        if b < a:
            a, b = a, a
        sl = np.frombuffer(heap[a:b], dtype=np.uint8).copy() if b > a else np.zeros(0, dtype=np.uint8)
        out.append(sl)
        lengths[i] = sl.size
    return out, lengths


def _col(lib, batch_ptr, section: int, col_id: int, typ_hint: Optional[int] = None):
    typ = ctypes.c_int(0)
    n = ctypes.c_uint32(0)
    data = ctypes.c_void_p()
    valid = ctypes.c_void_p()
    offs = ctypes.c_void_p()
    st = lib.etap_col(
        batch_ptr,
        ctypes.c_uint16(section),
        ctypes.c_uint32(col_id),
        ctypes.byref(typ),
        ctypes.byref(n),
        ctypes.byref(data),
        ctypes.byref(valid),
        ctypes.byref(offs),
    )
    if st != C.ETAP_OK:
        return None
    typ_i = int(typ.value)
    n_i = int(n.value)
    if typ_i == C.ETAP_T_BYTES:
        values, lengths = _copy_varlen(data, offs, n_i)
        return {
            "type": typ_i,
            "n": n_i,
            "values": values,
            "lengths": lengths,
            "valid": _validity(valid, n_i),
        }
    arr = _copy_fixed(data, n_i, typ_hint if typ_hint is not None else typ_i)
    return {"type": typ_i, "n": n_i, "data": arr, "valid": _validity(valid, n_i)}


# ---------------------------------------------------------------------------
# In-memory batch
# ---------------------------------------------------------------------------

@dataclass
class PacketView:
    n: int
    pkt_id: np.ndarray
    flow_id: np.ndarray
    ts_ns: np.ndarray
    wire_len: np.ndarray
    cap_len: np.ndarray
    dir: np.ndarray
    ifindex: np.ndarray
    flags: np.ndarray
    l3_off: np.ndarray
    l4_off: np.ndarray
    bytes_len: np.ndarray
    valid: dict[str, np.ndarray]
    packet_bytes: list[np.ndarray]  # raw captured slices, uint8 tensors (copied)


@dataclass
class ParseView:
    n: int
    pkt_id: np.ndarray
    msg_id: np.ndarray
    proto_id: np.ndarray
    msg_off: np.ndarray
    msg_len: np.ndarray
    flags: np.ndarray
    ipv4_src: np.ndarray  # (N, 4) uint8
    ipv4_dst: np.ndarray
    tcp_sport: np.ndarray
    tcp_dport: np.ndarray
    tls_sni: list[np.ndarray]
    http_host: list[np.ndarray]
    valid: dict[str, np.ndarray]


@dataclass
class FlowView:
    n: int
    flow_id: np.ndarray
    event: np.ndarray
    state: np.ndarray
    flags: np.ndarray
    ifindex: np.ndarray
    start_ns: np.ndarray
    last_ns: np.ndarray
    pkt_id_first: np.ndarray
    pkt_id_last: np.ndarray
    pkts_fwd: np.ndarray
    pkts_rev: np.ndarray
    bytes_fwd: np.ndarray
    bytes_rev: np.ndarray
    duration: np.ndarray
    valid: dict[str, np.ndarray]


@dataclass
class EtapBatch:
    """Copied columnar tensors from one ETAP batch. No JSON / text logs."""

    batch_id: int
    seq: int
    epoch: int
    schema_id: int
    flags: int
    time_first_ns: int
    time_last_ns: int
    packet: PacketView
    parse: ParseView
    flow: FlowView


def _empty_valid(n: int, present: bool = False) -> np.ndarray:
    return np.ones(n, dtype=np.bool_) if present else np.zeros(n, dtype=np.bool_)


def _meta_or_zero(col, n: int, dtype, shape_extra=None):
    if col is None:
        shp = (n,) + (shape_extra or ())
        return np.zeros(shp, dtype=dtype), _empty_valid(n, False)
    return col["data"], col["valid"]


def _find_section(lib, batch_ptr, hdr, kind: int) -> Optional[EtapSection]:
    size = ctypes.c_uint32(0)
    base = lib.etap_batch_data(batch_ptr, ctypes.byref(size))
    if not base or int(hdr.n_sections) == 0:
        return None
    dir_addr = base + int(hdr.sections_off)
    for i in range(int(hdr.n_sections)):
        sec = EtapSection.from_buffer_copy(ctypes.string_at(dir_addr + i * ctypes.sizeof(EtapSection), ctypes.sizeof(EtapSection)))
        if int(sec.kind) == kind:
            return sec
    return None


def _copy_packet_bytes(lib, batch_ptr, hdr, n_pkt: int) -> list[np.ndarray]:
    """Copy PACKET_BYTES slices using offsets/lengths from packet meta (not a by-value span)."""
    out: list[np.ndarray] = [np.zeros(0, dtype=np.uint8) for _ in range(n_pkt)]
    sec = _find_section(lib, batch_ptr, hdr, C.ETAP_SEC_PACKET_BYTES)
    if sec is None or n_pkt == 0:
        return out
    off_c = _col(lib, batch_ptr, C.ETAP_SEC_PACKET_META, C.ETAP_COL_BYTES_OFF, C.ETAP_T_U32)
    len_c = _col(lib, batch_ptr, C.ETAP_SEC_PACKET_META, C.ETAP_COL_BYTES_LEN, C.ETAP_T_U32)
    if off_c is None or len_c is None:
        return out
    size = ctypes.c_uint32(0)
    base = lib.etap_batch_data(batch_ptr, ctypes.byref(size))
    if not base:
        return out
    total = int(size.value)
    for i in range(min(n_pkt, int(off_c["n"]), int(len_c["n"]))):
        off = int(off_c["data"][i])
        ln = int(len_c["data"][i])
        start = int(sec.off) + off
        if ln <= 0 or start < 0 or start + ln > total or off + ln > int(sec.size):
            continue
        out[i] = np.frombuffer(ctypes.string_at(base + start, ln), dtype=np.uint8).copy()
    return out


def copy_batch(lib, batch_ptr) -> EtapBatch:
    hdr_p = lib.etap_batch_header(batch_ptr)
    if not hdr_p:
        raise RuntimeError("etap_batch_header returned NULL")
    hdr = ctypes.cast(hdr_p, ctypes.POINTER(EtapBatchHdr)).contents
    n_pkt = int(hdr.n_packets)
    n_parse = int(hdr.n_parse_rows)
    n_flow = int(hdr.n_flows)

    def pcol(col_id, typ=None):
        return _col(lib, batch_ptr, C.ETAP_SEC_PACKET_META, col_id, typ)

    pkt_id, pkt_id_v = _meta_or_zero(pcol(C.ETAP_COL_PKT_ID, C.ETAP_T_U64), n_pkt, np.uint64)
    flow_id, flow_id_v = _meta_or_zero(pcol(C.ETAP_COL_FLOW_ID, C.ETAP_T_U64), n_pkt, np.uint64)
    ts_ns, ts_v = _meta_or_zero(pcol(C.ETAP_COL_TS_NS, C.ETAP_T_TS_NS), n_pkt, np.uint64)
    wire, wire_v = _meta_or_zero(pcol(C.ETAP_COL_WIRE_LEN, C.ETAP_T_U32), n_pkt, np.uint32)
    cap, cap_v = _meta_or_zero(pcol(C.ETAP_COL_CAP_LEN, C.ETAP_T_U32), n_pkt, np.uint32)
    direc, dir_v = _meta_or_zero(pcol(C.ETAP_COL_DIR, C.ETAP_T_U8), n_pkt, np.uint8)
    ifx, ifx_v = _meta_or_zero(pcol(C.ETAP_COL_IFINDEX, C.ETAP_T_U32), n_pkt, np.uint32)
    flags, flags_v = _meta_or_zero(pcol(C.ETAP_COL_FLAGS, C.ETAP_T_U16), n_pkt, np.uint16)
    l3, l3_v = _meta_or_zero(pcol(C.ETAP_COL_L3_OFF, C.ETAP_T_U16), n_pkt, np.uint16)
    l4, l4_v = _meta_or_zero(pcol(C.ETAP_COL_L4_OFF, C.ETAP_T_U16), n_pkt, np.uint16)
    blen_col = pcol(C.ETAP_COL_BYTES_LEN, C.ETAP_T_U32)
    if blen_col is not None:
        blen, blen_v = blen_col["data"], blen_col["valid"]
    else:
        blen, blen_v = np.zeros(n_pkt, dtype=np.uint32), _empty_valid(n_pkt, False)

    packet_bytes = _copy_packet_bytes(lib, batch_ptr, hdr, n_pkt)
    if blen_col is None:
        for i, sl in enumerate(packet_bytes):
            blen[i] = sl.size
            blen_v[i] = sl.size > 0

    packet = PacketView(
        n=n_pkt,
        pkt_id=pkt_id,
        flow_id=flow_id,
        ts_ns=ts_ns,
        wire_len=wire,
        cap_len=cap,
        dir=direc,
        ifindex=ifx,
        flags=flags,
        l3_off=l3,
        l4_off=l4,
        bytes_len=blen,
        valid={
            "pkt_id": pkt_id_v,
            "flow_id": flow_id_v,
            "ts_ns": ts_v,
            "wire_len": wire_v,
            "cap_len": cap_v,
            "dir": dir_v,
            "ifindex": ifx_v,
            "flags": flags_v,
            "l3_off": l3_v,
            "l4_off": l4_v,
            "bytes_len": blen_v,
        },
        packet_bytes=packet_bytes,
    )

    nidx = ctypes.c_uint32(0)
    idx_ptr = lib.etap_parse_index(batch_ptr, ctypes.byref(nidx))
    n_idx = int(nidx.value)
    if idx_ptr and n_idx:
        raw = ctypes.string_at(idx_ptr, n_idx * 32)
        rows = np.frombuffer(raw, dtype=np.dtype(C.PARSE_INDEX_DTYPE)).copy()
        p_pkt = rows["pkt_id"]
        p_msg = rows["msg_id"]
        p_proto = rows["proto_id"]
        p_off = rows["msg_off"]
        p_len = rows["msg_len"]
        p_flags = rows["flags"]
    else:
        n_idx = n_parse
        p_pkt = np.zeros(n_idx, dtype=np.uint64)
        p_msg = np.zeros(n_idx, dtype=np.uint64)
        p_proto = np.zeros(n_idx, dtype=np.uint32)
        p_off = np.zeros(n_idx, dtype=np.uint16)
        p_len = np.zeros(n_idx, dtype=np.uint16)
        p_flags = np.zeros(n_idx, dtype=np.uint16)
    # If the index section is missing, n_idx may still be the header count.
    n_idx = int(p_pkt.shape[0])

    def fcol(fid, typ=None):
        return _col(lib, batch_ptr, C.ETAP_SEC_PARSE_COLS, fid, typ)

    src_c = fcol(C.ETAP_FLD_IPV4_SRC, C.ETAP_T_IPV4)
    dst_c = fcol(C.ETAP_FLD_IPV4_DST, C.ETAP_T_IPV4)
    sp_c = fcol(C.ETAP_FLD_TCP_SPORT, C.ETAP_T_U16)
    dp_c = fcol(C.ETAP_FLD_TCP_DPORT, C.ETAP_T_U16)
    sni_c = fcol(C.ETAP_FLD_TLS_SNI, C.ETAP_T_BYTES)
    host_c = fcol(C.ETAP_FLD_HTTP_HOST, C.ETAP_T_BYTES)

    ipv4_src, src_v = (
        (src_c["data"], src_c["valid"]) if src_c else (np.zeros((n_idx, 4), dtype=np.uint8), _empty_valid(n_idx))
    )
    ipv4_dst, dst_v = (
        (dst_c["data"], dst_c["valid"]) if dst_c else (np.zeros((n_idx, 4), dtype=np.uint8), _empty_valid(n_idx))
    )
    sport, sport_v = (
        (sp_c["data"], sp_c["valid"]) if sp_c else (np.zeros(n_idx, dtype=np.uint16), _empty_valid(n_idx))
    )
    dport, dport_v = (
        (dp_c["data"], dp_c["valid"]) if dp_c else (np.zeros(n_idx, dtype=np.uint16), _empty_valid(n_idx))
    )
    if sni_c:
        tls_sni, sni_v = sni_c["values"], sni_c["valid"]
    else:
        tls_sni, sni_v = [np.zeros(0, dtype=np.uint8) for _ in range(n_idx)], _empty_valid(n_idx)
    if host_c:
        http_host, host_v = host_c["values"], host_c["valid"]
    else:
        http_host, host_v = [np.zeros(0, dtype=np.uint8) for _ in range(n_idx)], _empty_valid(n_idx)

    parse = ParseView(
        n=n_idx,
        pkt_id=p_pkt,
        msg_id=p_msg,
        proto_id=p_proto,
        msg_off=p_off,
        msg_len=p_len,
        flags=p_flags,
        ipv4_src=ipv4_src,
        ipv4_dst=ipv4_dst,
        tcp_sport=sport,
        tcp_dport=dport,
        tls_sni=tls_sni,
        http_host=http_host,
        valid={
            "index": np.ones(n_idx, dtype=np.bool_) if n_idx else np.zeros(0, dtype=np.bool_),
            "ipv4_src": src_v,
            "ipv4_dst": dst_v,
            "tcp_sport": sport_v,
            "tcp_dport": dport_v,
            "tls_sni": sni_v,
            "http_host": host_v,
        },
    )

    nf = ctypes.c_uint32(0)
    fm_ptr = lib.etap_flow_meta(batch_ptr, ctypes.byref(nf))
    n_f = int(nf.value)
    if fm_ptr and n_f:
        raw = ctypes.string_at(fm_ptr, n_f * 48)
        fr = np.frombuffer(raw, dtype=np.dtype(C.FLOW_META_DTYPE)).copy()
        f_id, ev, st, flg, fif = fr["flow_id"], fr["event"], fr["state"], fr["flags"], fr["ifindex"]
        t0, t1 = fr["start_ns"], fr["last_ns"]
        p0, p1 = fr["pkt_id_first"], fr["pkt_id_last"]
    else:
        n_f = n_flow
        f_id = np.zeros(n_f, dtype=np.uint64)
        ev = np.zeros(n_f, dtype=np.uint8)
        st = np.zeros(n_f, dtype=np.uint8)
        flg = np.zeros(n_f, dtype=np.uint16)
        fif = np.zeros(n_f, dtype=np.uint32)
        t0 = np.zeros(n_f, dtype=np.uint64)
        t1 = np.zeros(n_f, dtype=np.uint64)
        p0 = np.zeros(n_f, dtype=np.uint64)
        p1 = np.zeros(n_f, dtype=np.uint64)

    def feat(fid):
        return _col(lib, batch_ptr, C.ETAP_SEC_FLOW_FEAT, fid, C.ETAP_T_U64)

    def feat_arr(fid):
        c = feat(fid)
        if c is None:
            return np.zeros(n_f, dtype=np.uint64), _empty_valid(n_f)
        return c["data"].astype(np.uint64, copy=False), c["valid"]

    pkts_fwd, pkts_fwd_v = feat_arr(C.ETAP_FEAT_PKTS_FWD)
    pkts_rev, pkts_rev_v = feat_arr(C.ETAP_FEAT_PKTS_REV)
    bytes_fwd, bytes_fwd_v = feat_arr(C.ETAP_FEAT_BYTES_FWD)
    bytes_rev, bytes_rev_v = feat_arr(C.ETAP_FEAT_BYTES_REV)
    duration, duration_v = feat_arr(C.ETAP_FEAT_DURATION)

    flow = FlowView(
        n=n_f,
        flow_id=f_id,
        event=ev,
        state=st,
        flags=flg,
        ifindex=fif,
        start_ns=t0,
        last_ns=t1,
        pkt_id_first=p0,
        pkt_id_last=p1,
        pkts_fwd=pkts_fwd,
        pkts_rev=pkts_rev,
        bytes_fwd=bytes_fwd,
        bytes_rev=bytes_rev,
        duration=duration,
        valid={
            "meta": np.ones(n_f, dtype=np.bool_) if n_f else np.zeros(0, dtype=np.bool_),
            "pkts_fwd": pkts_fwd_v,
            "pkts_rev": pkts_rev_v,
            "bytes_fwd": bytes_fwd_v,
            "bytes_rev": bytes_rev_v,
            "duration": duration_v,
        },
    )

    return EtapBatch(
        batch_id=int(hdr.batch_id),
        seq=int(hdr.seq),
        epoch=int(hdr.epoch),
        schema_id=int(hdr.schema_id),
        flags=int(hdr.flags),
        time_first_ns=int(hdr.time_first_ns),
        time_last_ns=int(hdr.time_last_ns),
        packet=packet,
        parse=parse,
        flow=flow,
    )


class EtapSim:
    """Open etap://sim, discover, subscribe to all three views, poll copied batches."""

    def __init__(
        self,
        lib_path: Optional[os.PathLike] = None,
        max_records: int = 8,
        max_pkt_bytes: int = 128,
    ):
        self.lib = load_lib(lib_path)
        self.max_records = max_records
        self.max_pkt_bytes = max_pkt_bytes
        self._conn = ctypes.c_void_p()
        self._sub = ctypes.c_void_p()
        self._opened = False

    def open(self) -> "EtapSim":
        st = self.lib.etap_open(b"etap://sim", None, ctypes.byref(self._conn))
        if st != C.ETAP_OK or not self._conn:
            raise RuntimeError(f"etap_open(etap://sim) failed: {st}")
        caps = ctypes.c_void_p()
        st = self.lib.etap_discover(self._conn, ctypes.byref(caps))
        if st != C.ETAP_OK or not caps:
            self.close()
            raise RuntimeError(f"etap_discover failed: {st}")
        try:
            hdr_p = self.lib.etap_caps_header(caps)
            if not hdr_p:
                raise RuntimeError("etap_caps_header returned NULL")
            ch = ctypes.cast(hdr_p, ctypes.POINTER(EtapCapsHdr)).contents
            if int(ch.magic) != C.ETAP_MAGIC:
                raise RuntimeError(f"unexpected caps magic {ch.magic:#x}")
        finally:
            self.lib.etap_caps_free(caps)

        req = build_full_req(max_records=self.max_records, max_pkt_bytes=self.max_pkt_bytes)
        buf = ctypes.create_string_buffer(req)
        sub_req = EtapSubReq(ctypes.cast(buf, ctypes.c_void_p), len(req))
        st = self.lib.etap_subscribe(self._conn, ctypes.byref(sub_req), ctypes.byref(self._sub))
        if st != C.ETAP_OK or not self._sub:
            self.close()
            raise RuntimeError(f"etap_subscribe failed: {st}")
        self._opened = True
        return self

    def poll(self, timeout_us: int = 0) -> Optional[EtapBatch]:
        if not self._opened:
            raise RuntimeError("EtapSim is not open")
        batch = ctypes.c_void_p()
        st = self.lib.etap_poll(self._sub, ctypes.c_uint32(timeout_us), ctypes.byref(batch))
        if st == C.ETAP_EMPTY:
            return None
        if st != C.ETAP_OK or not batch:
            raise RuntimeError(f"etap_poll failed: {st}")
        try:
            return copy_batch(self.lib, batch)
        finally:
            self.lib.etap_release(batch)

    def close(self) -> None:
        if self._sub:
            self.lib.etap_unsubscribe(self._sub)
            self._sub = ctypes.c_void_p()
        if self._conn:
            self.lib.etap_close(self._conn)
            self._conn = ctypes.c_void_p()
        self._opened = False

    def __enter__(self) -> "EtapSim":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()
