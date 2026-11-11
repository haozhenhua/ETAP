"""Deterministic supervision from simulator columns (no human-written prose)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from etap_encoder.batch import EtapBatch
from etap_encoder.constants import (
    ETAP_FLOW_EV_ANOMALY,
    ETAP_FLOW_EV_EXPIRE,
    ETAP_FLOW_EV_NEW,
    ETAP_FLOW_EV_RESET,
    ETAP_FLOW_EV_UPDATE,
    ETAP_PROTO_ETH,
    ETAP_PROTO_HTTP,
    ETAP_PROTO_IPV4,
    ETAP_PROTO_TCP,
    ETAP_PROTO_TLS,
)

Task = Literal["protocol", "dport", "event"]
TASKS: tuple[Task, ...] = ("protocol", "dport", "event")

PREFIX = "ETAP traffic."

QUESTIONS = {
    "protocol": "protocol?",
    "dport": "dport?",
    "event": "event?",
}

PROTO_ANSWER = {
    ETAP_PROTO_ETH: "eth",
    ETAP_PROTO_IPV4: "ipv4",
    ETAP_PROTO_TCP: "tcp",
    ETAP_PROTO_TLS: "tls",
    ETAP_PROTO_HTTP: "http",
}

EVENT_ANSWER = {
    ETAP_FLOW_EV_NEW: "new",
    ETAP_FLOW_EV_UPDATE: "update",
    ETAP_FLOW_EV_EXPIRE: "expire",
    ETAP_FLOW_EV_RESET: "reset",
    ETAP_FLOW_EV_ANOMALY: "anomaly",
}


@dataclass(frozen=True)
class SupervisedExample:
    task: Task
    prefix: str
    question: str
    answer: str


def protocol_answer(batch: EtapBatch) -> str:
    if batch.parse.n == 0:
        return "unknown"
    # First parse row; the simulator writes a concrete proto_id, not a string.
    proto = int(batch.parse.proto_id[0])
    return PROTO_ANSWER.get(proto, "unknown")


def dport_answer(batch: EtapBatch) -> str:
    ports = batch.parse.tcp_dport
    valid = batch.parse.valid["tcp_dport"]
    if ports.size == 0 or not valid.any():
        return "other"
    port = int(ports[int(valid.argmax())])
    if port == 80:
        return "http"
    if port == 443:
        return "https"
    return "other"


def event_answer(batch: EtapBatch) -> str:
    if batch.flow.n == 0:
        return "unknown"
    ev = int(batch.flow.event[0])
    if ev in EVENT_ANSWER:
        return EVENT_ANSWER[ev]
    # If several flag bits were packed, name the lowest set bit.
    for bit, name in EVENT_ANSWER.items():
        if ev & bit:
            return name
    return "unknown"


_ANSWER_FN = {
    "protocol": protocol_answer,
    "dport": dport_answer,
    "event": event_answer,
}


def derive_example(batch: EtapBatch, task: Task = "protocol") -> SupervisedExample:
    if task not in _ANSWER_FN:
        raise ValueError(f"unknown task {task!r}")
    return SupervisedExample(
        task=task,
        prefix=PREFIX,
        question=QUESTIONS[task],
        answer=_ANSWER_FN[task](batch),
    )
