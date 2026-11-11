# ETAP encoder

This directory will hold the encoder that maps ETAP batches onto a model’s input representation.

Design intent:

- Consume the three ETAP views (packet, parse, flow) as typed columnar batches, correlated by unified IDs.
- Do not convert traffic into JSON, logs, or natural language on the data path.
- Project numeric columns, embed categorical IDs, and encode packet-byte slices, then align the result to a model’s hidden size.
- A first implementation can freeze a base LLM (for example a Qwen-class model) and train only this adapter. A later option is a dedicated ETAP encoder, similar to a vision encoder in a multimodal model, whose outputs live in the same representation space as text tokens.

The C interface and in-process simulator (`etap://sim`) in this repository are the source of batches for encoder development. Implementation of the neural adapter is not in this first commit.
