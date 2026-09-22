# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Zero-dependency gateway metrics: counters + Prometheus text.

Stdlib only. The gateway runs by default as a stdio child of an agent
host, so this module must import and work with no third-party packages.

``observe_tool_call`` records per-(tool, tenant, ok) counts and latency
into in-memory structures; ``render_prometheus`` exposes them in
Prometheus text exposition format for the gateway's ``/metrics`` route.

Per-call detail lives in the on-file log (``bonnet.core.logging`` via
``tools._gw_log`` and the middleware start/finish lines) — this module
carries only the aggregated RED counters, never traces or spans.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any

# Histogram buckets (milliseconds) for tool latency. Fixed set keeps /metrics
# cardinality bounded: one cumulative series per bucket per (tool, tenant).
_BUCKETS_MS = (5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000)

_lock = threading.Lock()
_enabled = True
_service_name = "bonnet-gateway"
_start_time = time.time()

# (tool, tenant, ok) -> count
_calls: dict[tuple[str, str, str], int] = {}
# (tool, tenant) -> [count, sum_ms]
_latency: dict[tuple[str, str], list[float]] = {}
# (tool, tenant, le) -> cumulative count, where le is bucket upper bound or "+Inf"
_buckets: dict[tuple[str, str, str], int] = {}


def _norm_tenant(tenant: Any) -> str:
    try:
        s = str(tenant or "unknown")
    except Exception:
        s = "unknown"
    s = s.strip() or "unknown"
    # Bound label cardinality: tenant ids are operator-chosen but a runaway
    # client must not mint unbounded series.
    return s[:32]


def _norm_tool(op: Any) -> str:
    try:
        s = str(op or "unknown")
    except Exception:
        s = "unknown"
    return (s.strip() or "unknown")[:64]


def init_metrics(
    *,
    enabled: bool | None = None,
    service_name: str | None = None,
) -> bool:
    """Enable/disable the built-in counters. Never raises.

    ``enabled=False`` (via ``BONNET_METRICS_ENABLED=0`` or
    ``gateway.toml metrics_enabled=false``) makes ``observe_tool_call`` a no-op
    and ``render_prometheus`` report only the ``up`` gauge. Returns whether
    counters are enabled.
    """
    global _enabled, _service_name
    try:
        if enabled is None:
            raw = os.environ.get("BONNET_METRICS_ENABLED", "").strip().lower()
            enabled = raw not in ("0", "false", "no", "off")
        _enabled = bool(enabled)
        if service_name:
            _service_name = service_name.strip() or _service_name
        return _enabled
    except Exception:
        return False


def reset_for_tests() -> None:
    """Clear all counters. Tests only; not part of the operator surface."""
    with _lock:
        _calls.clear()
        _latency.clear()
        _buckets.clear()


def observe_tool_call(
    op: str,
    *,
    ok: bool = True,
    tenant: str = "",
    duration_ms: float | None = None,
) -> None:
    """Record one gateway tool call. Never raises; no-op when disabled.

    Counts are the primary signal. ``duration_ms`` feeds the latency
    histogram when the caller measured it (middleware does); ``None``
    records only the count. Per-call detail (origin, args, error) belongs
    in the file log, not in metric labels.
    """
    try:
        if not _enabled:
            return
        tool = _norm_tool(op)
        ten = _norm_tenant(tenant)
        ok_s = "true" if ok else "false"
        with _lock:
            key = (tool, ten, ok_s)
            _calls[key] = _calls.get(key, 0) + 1
            if duration_ms is not None:
                try:
                    ms = float(duration_ms)
                except (TypeError, ValueError):
                    ms = -1.0
                if ms >= 0:
                    lkey = (tool, ten)
                    entry = _latency.get(lkey)
                    if entry is None:
                        entry = _latency[lkey] = [0, 0.0]
                    entry[0] += 1
                    entry[1] += ms
                    for b in _BUCKETS_MS:
                        if ms <= b:
                            bkey = (tool, ten, str(b))
                            _buckets[bkey] = _buckets.get(bkey, 0) + 1
                    _buckets[(tool, ten, "+Inf")] = _buckets.get((tool, ten, "+Inf"), 0) + 1
    except Exception:
        pass


def _esc(s: str) -> str:
    return s.replace("\\", r"\\").replace('"', r"\"").replace("\n", r"\n")


def render_prometheus() -> str:
    """Render built-in counters in Prometheus text exposition format."""
    lines = [
        "# HELP bonnet_gateway_up 1 while the gateway metrics endpoint serves.",
        "# TYPE bonnet_gateway_up gauge",
        "bonnet_gateway_up 1",
        "# HELP bonnet_gateway_tool_calls_total Gateway MCP tool calls by tool, tenant and outcome.",
        "# TYPE bonnet_gateway_tool_calls_total counter",
    ]
    with _lock:
        for tool, ten, ok_s in sorted(_calls):
            lines.append(
                f'bonnet_gateway_tool_calls_total{{tool="{_esc(tool)}",'
                f'tenant="{_esc(ten)}",ok="{ok_s}"}} {_calls[(tool, ten, ok_s)]}'
            )
        lines += [
            "# HELP bonnet_gateway_tool_latency_ms_sum Total tool latency in ms.",
            "# TYPE bonnet_gateway_tool_latency_ms_sum counter",
        ]
        for tool, ten in sorted(_latency):
            count, total = _latency[(tool, ten)]
            lines.append(
                f'bonnet_gateway_tool_latency_ms_sum{{tool="{_esc(tool)}",'
                f'tenant="{_esc(ten)}"}} {total:.3f}'
            )
        lines += [
            "# HELP bonnet_gateway_tool_latency_ms_count Tool calls with a measured latency.",
            "# TYPE bonnet_gateway_tool_latency_ms_count counter",
        ]
        for tool, ten in sorted(_latency):
            count, _ = _latency[(tool, ten)]
            lines.append(
                f'bonnet_gateway_tool_latency_ms_count{{tool="{_esc(tool)}",'
                f'tenant="{_esc(ten)}"}} {int(count)}'
            )
        lines += [
            "# HELP bonnet_gateway_tool_latency_ms_bucket Cumulative latency histogram.",
            "# TYPE bonnet_gateway_tool_latency_ms_bucket histogram",
        ]
        pairs = sorted({(t, ten) for (t, ten, _ok) in _calls} | set(_latency))
        for tool, ten in pairs:
            for b in list(_BUCKETS_MS) + ["+Inf"]:
                le = str(b)
                n = _buckets.get((tool, ten, le), 0)
                lines.append(
                    f'bonnet_gateway_tool_latency_ms_bucket{{tool="{_esc(tool)}",'
                    f'tenant="{_esc(ten)}",le="{le}"}} {n}'
                )
    lines.append("")
    return "\n".join(lines)


def snapshot() -> dict[str, Any]:
    """JSON-serializable copy of the counters (tests/debugging)."""
    with _lock:
        return {
            "service": _service_name,
            "enabled": _enabled,
            "uptime_s": round(time.time() - _start_time, 1),
            "calls": {f"{t}|{ten}|{ok_s}": n for (t, ten, ok_s), n in _calls.items()},
        }
