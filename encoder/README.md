# ETAP encoder

Minimal adapter that maps ETAP’s three columnar views (packet, parse, flow) onto a language-model hidden size, starting with [Qwen3.5-2B-Base](https://huggingface.co/Qwen/Qwen3.5-2B-Base) (`hidden_size=2048`).

The data path does **not** convert traffic into JSON, logs, hex dumps, or natural-language packet descriptions. Batches come from the C API (`etap://sim` or a later live port) as typed tensors with validity bitmaps. Packet bytes and variable-length fields (TLS SNI, HTTP Host) are consumed as byte patches, not tokenized as text.

The first training mode freezes the language model (embeddings, backbone, `lm_head`) and trains only this adapter. Inputs are stitched with `inputs_embeds`: frozen text embeddings of a short prefix, adapter tokens (flow → packet → parse), then frozen embeddings of a short question. The tokenizer is not resized. Supervision comes from simulator columns (protocol, destination-port class, flow event).

Default tests and training use `FakeQwen`, a same-width stand-in, so nothing downloads the 2B weights. How to run that path, and how to attach the real Qwen3.5-2B-Base later, is in [docs/train-adapter-only.md](docs/train-adapter-only.md)（中文：「只训适配器就能先跑通」）.

## Layout

| Path | Role |
| --- | --- |
| `etap_encoder/` | Python package: ctypes batch reader, three-view encoder, FakeQwen, labels, training loop |
| `scripts/train_adapter.py` | CLI (`--model fake` by default; `--model Qwen/Qwen3.5-2B-Base` is documented, not used by tests) |
| `tests/` | CPU unit tests against `libetap.so` and `etap://sim` |
| `docs/train-adapter-only.md` | Freeze list, stitching, simulator labels, command recipe |
| `requirements.txt` | `torch` + `numpy` (install the CPU wheel) |

## Install and test

From the repository root (GCC is required to build `build/libetap.so`):

```bash
./build.sh && ./build/test_etap

python3 -m venv encoder/.venv
. encoder/.venv/bin/activate
pip install -r encoder/requirements.txt --index-url https://download.pytorch.org/whl/cpu

PYTHONPATH=encoder python -m unittest discover -s encoder/tests -v
PYTHONPATH=encoder python encoder/scripts/train_adapter.py --steps 5 --device cpu
```

`.venv` is gitignored and must not be committed.
