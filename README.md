# ETAP

**Ethernet Traffic Awareness Port** — an encoder that adapts live Ethernet traffic into model-ready views so large language models can consume network data without turning it into text.

## Vision

Networks produce a continuous stream of binary traffic; language models natively consume tokenized text. The usual bridges — hex dumps, logs, JSON, or natural-language packet write-ups — are low density and lossy, and they train the model to read prose rather than traffic.

This repository exists to close that gap. ETAP is a machine-facing port that exposes live Ethernet traffic as typed, high-density observation batches. An ETAP encoder then maps those batches into a model's representation space, in the same spirit as a vision encoder for images, so many base models can consume network data without a text conversion on the data path.

The near-term path is a lightweight adapter: freeze the language model, project the packet / parse / flow views into its hidden size, and inject them with `inputs_embeds`. The longer-term aim is a dedicated ETAP encoder that can be attached to various base models without rewriting their language core.

## Why ETAP

Language models normally ingest tokenized text. Dumping packet hex, logs, or JSON into a context window is low density and trains the model to read prose, not traffic. ETAP instead exposes a machine-facing port:

- A low-frequency control plane to discover capabilities and to establish or adjust a subscription.
- A high-throughput data plane that delivers **traffic observation batches** with a machine-readable schema.
- Three correlated views — **packet**, **parse**, and **flow** — joined by unified IDs (`pkt_id`, `flow_id`, timestamps, and related identifiers).
- Packet bytes in a contiguous buffer, parse results as typed columns, variable-length fields via offset/length, and validity bitmaps so “not observed” is not treated as “did not happen.”
- Overflow is handled by sampling, aggregation, or dropping, with gap reports on the batch rather than by blocking the data plane.

The interface specification is in [docs/ETAP-interface-spec.md](docs/ETAP-interface-spec.md).

## What’s in this repository

| Path | Role |
| --- | --- |
| `etap.h`, `src/etap.c` | C reference implementation of the ETAP API |
| `tests/test_etap.c` | Interface verification suite |
| `build.sh` | Build the library and tests with system `gcc` (no `make`/`cmake` required) |
| `docs/ETAP-interface-spec.md` | Interface specification |
| `encoder/` | Minimal Qwen3.5 adapter (three-view encoder, FakeQwen training path) and [encoder/docs/train-adapter-only.md](encoder/docs/train-adapter-only.md) |

The reference implementation includes an in-process simulator, `etap://sim`, so you can subscribe, poll batches, and run the tests without a NIC.

## Build and test

Requires GCC with C11 and pthreads (verified with GCC 14 on Debian):

```bash
./build.sh && ./build/test_etap
```

The suite checks discovery, subscription, 128-byte batch headers, alignment of the three views, on-demand column selection, gap and truncation flags, end-of-stream `EMPTY`, and schema/epoch changes after a destructive resubscribe.

## Encoder roadmap

A first adapter lives in [`encoder/`](encoder/). It reads `etap://sim` batches as columnar tensors, encodes the packet / parse / flow views, and injects them into a frozen language model with `inputs_embeds`. Tests and the default training loop use a same-width FakeQwen stand-in (no 2B download). See [`encoder/README.md`](encoder/README.md) and [`encoder/docs/train-adapter-only.md`](encoder/docs/train-adapter-only.md) for how to train the adapter only and get a first working run.

1. Keep the ETAP C API as the source of live or simulated batches.
2. (Done, minimal) An adapter that projects packet / parse / flow columns into tensors (numeric projection, categorical embeddings, a small byte encoder) and aligns them to a model hidden size (2048 for Qwen3.5-2B-Base).
3. Train the adapter first with the language model frozen; optionally continue-pretrain or fine-tune the base model so it can read the packed representation.
4. Optionally add a dedicated ETAP encoder, in the same spirit as a vision encoder, and attach it to various base models rather than changing their language core.

## License

No license has been chosen yet. All rights remain with the repository owner.
