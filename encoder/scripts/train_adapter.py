#!/usr/bin/env python3
"""CLI: train only the ETAP adapter on etap://sim (FakeQwen by default)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from etap_encoder.constants import QWEN35_2B_BASE
from etap_encoder.train import train_adapter


def main() -> int:
    p = argparse.ArgumentParser(
        description=(
            "Freeze the language model and train only the ETAP adapter on "
            "simulator labels. Default model is FakeQwen (no download)."
        )
    )
    p.add_argument("--steps", type=int, default=5, help="optimizer steps (one sim batch each)")
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--max-records", type=int, default=8, help="packets per sim batch")
    p.add_argument("--lib", default=None, help="path to libetap.so (default: repo build/)")
    p.add_argument(
        "--model",
        default="fake",
        help=(
            "fake (default, no download) or a Hugging Face id such as "
            f"{QWEN35_2B_BASE}. The real-model path is not used by tests."
        ),
    )
    p.add_argument("--device", default="cpu")
    p.add_argument("--seed", type=int, default=0)
    args = p.parse_args()
    model_id = None if args.model in ("fake", "FakeQwen") else args.model
    result = train_adapter(
        steps=args.steps,
        lr=args.lr,
        max_records=args.max_records,
        lib_path=args.lib,
        model_id=model_id,
        device=args.device,
        seed=args.seed,
    )
    print(f"model={result['model_id']} hidden_size={result['hidden_size']} steps={result['steps']}")
    print(f"trainable_params={len(result['trainable'])}")
    for i, (loss, ans) in enumerate(zip(result["losses"], result["answers"])):
        print(f"  step {i}: loss={loss:.4f} answer={ans}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
