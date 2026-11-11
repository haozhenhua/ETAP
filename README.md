# ETAP

**Ethernet Traffic Awareness Port** — an encoder that adapts live Ethernet traffic into model-ready views so large language models can consume network data without turning it into text.

中文摘要：本仓库的目标是开发 ETAP 编码器，把网络实时流量接入并适配各类大模型。数据通路不把流量转换成 JSON、日志或自然语言；模型消费的是报文、解析、流三种高密度列式视图。

## Why ETAP

Language models normally ingest tokenized text. Dumping packet hex, logs, or JSON into a context window is low density and trains the model to read prose, not traffic. ETAP instead exposes a machine-facing port:

- A low-frequency control plane to discover capabilities and to establish or adjust a subscription.
- A high-throughput data plane that delivers **traffic observation batches** with a machine-readable schema.
- Three correlated views — **packet**, **parse**, and **flow** — joined by unified IDs (`pkt_id`, `flow_id`, timestamps, and related identifiers).
- Packet bytes in a contiguous buffer, parse results as typed columns, variable-length fields via offset/length, and validity bitmaps so “not observed” is not treated as “did not happen.”
- Overflow is handled by sampling, aggregation, or dropping, with gap reports on the batch rather than by blocking the data plane.

The interface specification (Chinese) is in [docs/ETAP-interface-spec.md](docs/ETAP-interface-spec.md).

## What’s in this repository

| Path | Role |
| --- | --- |
| `etap.h`, `src/etap.c` | C reference implementation of the ETAP API |
| `tests/test_etap.c` | Interface verification suite |
| `build.sh` | Build the library and tests with system `gcc` (no `make`/`cmake` required) |
| `docs/ETAP-interface-spec.md` | Interface specification |
| `encoder/` | Placeholder for the model-side encoder / adapter |

The reference implementation includes an in-process simulator, `etap://sim`, so you can subscribe, poll batches, and run the tests without a NIC.

## Build and test

Requires GCC with C11 and pthreads (verified with GCC 14 on Debian):

```bash
./build.sh && ./build/test_etap
```

The suite checks discovery, subscription, 128-byte batch headers, alignment of the three views, on-demand column selection, gap and truncation flags, end-of-stream `EMPTY`, and schema/epoch changes after a destructive resubscribe.

## Encoder roadmap

1. Keep the ETAP C API as the source of live or simulated batches.
2. Implement an adapter that projects packet / parse / flow columns into tensors (numeric projection, categorical embeddings, a small byte encoder) and aligns them to a model hidden size.
3. Train the adapter first with the language model frozen; optionally continue-pretrain or fine-tune the base model so it can read the packed representation.
4. Optionally add a dedicated ETAP encoder, in the same spirit as a vision encoder, and attach it to various base models rather than changing their language core.

## License

No license has been chosen yet. All rights remain with the repository owner.
