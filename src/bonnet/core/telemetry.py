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

"""Zero-dependency gateway telemetry: counters + Prometheus text + OTel hooks.

Design constraints (laziness-compatible):

- This module must import and work with **stdlib only**. The gateway runs by
  default as a stdio child of an agent host; a hard dependency on
  ``opentelemetry-*`` would tax every install for a feature only the http
  deployment uses. All OTel SDK imports live behind ``try/except ImportError``
  inside functions, never at module top level.
- Two layers, deliberately split:

  1. **Built-in RED counters** (always available, no exporter needed).
     ``observe_tool_call`` records per-(tool, tenant, ok) counts and latency
     into in-memory structures; ``render_prometheus`` exposes them in
     Prometheus text exposition format for the gateway's ``/metrics`` route.
     No ``prometheus_client`` or OTel required.
  2. **OTel enrichment** (best-effort, active only when the operator installed
     ``opentelemetry-distro[otlp]`` and runs under ``opentelemetry-instrument``
     or called ``init_telemetry`` with an OTLP endpoint). ``tool_span`` opens
     a real span when a tracer is configured and degrades to a nullcontext
     otherwise; ``set_span_attributes`` stamps tenant/origin/ok onto whatever
     span auto-instrumentation already opened (the ASGI POST span).

Why both: in http mode every MCP call arrives as ``POST /mcp/``, so pure
zero-code auto-instrumentation yields one identically-named span per call.
The per-tool name/tenant/ok attributes — the actually useful dimensions —
can only come from inside the gateway (``tools._gw_log`` / middleware), which
is what this module carries.
"""

from __future__ import annotations

import contextlib
import os
import threading
import time
from collections.abc import Iterator
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

_otel_ready = False


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


def init_telemetry(
    *,
    enabled: bool | None = None,
    service_name: str | None = None,
) -> bool:
    """Enable/disable the built-in counters; opportunistically bridge OTel logging.

    ``enabled=False`` (via ``BONNET_METRICS_ENABLED=0`` or
    ``gateway.toml metrics_enabled=false``) makes ``observe_tool_call`` a no-op
    and ``render_prometheus`` report only the ``up`` gauge. Never raises.

    When the OTel SDK + logging instrumentation *are* installed, also
    instruments stdlib logging so file log lines carry trace/span ids
    (log correlation for free). Returns whether counters are enabled.
    """
    global _enabled, _service_name, _otel_ready
    try:
        if enabled is None:
            raw = os.environ.get("BONNET_METRICS_ENABLED", "").strip().lower()
            enabled = raw not in ("0", "false", "no", "off")
        _enabled = bool(enabled)
        if service_name or os.environ.get("OTEL_SERVICE_NAME"):
            _service_name = (service_name or os.environ["OTEL_SERVICE_NAME"]).strip() or _service_name
        try:
            from opentelemetry.instrumentation.logging import LoggingInstrumentor

            LoggingInstrumentor().instrument(set_logging_format=True)
            _otel_ready = True
        except ImportError:
            _otel_ready = False
        except Exception:
            pass
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
    origin: str = "",
) -> None:
    """Record one gateway tool call. Never raises; no-op when disabled.

    Counts are the primary signal (they work with zero OTel installed).
    ``duration_ms`` feeds the latency histogram when the caller measured it
    (middleware does); ``None`` records only the count. Also mirrors
    tenant/origin/ok onto the current OTel span when one exists, so the
    zero-code ASGI span gains the per-tool dimensions for free.
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
        set_span_attributes(
            **{"bonnet.tool": tool, "bonnet.tenant": ten, "bonnet.ok": ok_s,
               **({"bonnet.origin": str(origin)[:64]} if origin else {})}
        )
    except Exception:
        pass


@contextlib.contextmanager
def tool_span(op: str, **attrs: Any) -> Iterator[Any]:
    """Open a per-tool OTel span; nullcontext when OTel is absent.

    Usage: ``with tool_span("publish", tenant=t): ...``. Under
    ``opentelemetry-instrument`` this nests inside the auto-instrumented ASGI
    server span; without OTel it costs one contextmanager entry. Never raises
    during setup; body exceptions always propagate (the ``yield`` is never
    wrapped in a catching ``except``, which would corrupt the generator
    protocol with "generator didn't stop after throw()").
    """
    span_cm = None
    try:
        from opentelemetry import trace

        tracer = trace.get_tracer("bonnet.gateway")
        tool = _norm_tool(op)
        safe = {f"bonnet.{k}": str(v)[:128] for k, v in attrs.items() if v is not None}
        span_cm = tracer.start_as_current_span(f"gateway.{tool}", attributes=safe)
    except Exception:
        span_cm = None
    if span_cm is None:
        yield None
        return
    with span_cm as span:
        yield span


def set_span_attributes(**attrs: Any) -> None:
    """Stamp attributes onto the current span. No-op without OTel. Never raises."""
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        if span is not None and getattr(span, "is_recording", lambda: False)():
            span.set_attributes({k: str(v)[:128] for k, v in attrs.items()})
    except ImportError:
        pass
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
        for (tool, ten, ok_s) in sorted(_calls):
            lines.append(
                f'bonnet_gateway_tool_calls_total{{tool="{_esc(tool)}",'
                f'tenant="{_esc(ten)}",ok="{ok_s}"}} {_calls[(tool, ten, ok_s)]}'
            )
        lines += [
            "# HELP bonnet_gateway_tool_latency_ms_sum Total tool latency in ms.",
            "# TYPE bonnet_gateway_tool_latency_ms_sum counter",
        ]
        for (tool, ten) in sorted(_latency):
            count, total = _latency[(tool, ten)]
            lines.append(
                f'bonnet_gateway_tool_latency_ms_sum{{tool="{_esc(tool)}",'
                f'tenant="{_esc(ten)}"}} {total:.3f}'
            )
        lines += [
            "# HELP bonnet_gateway_tool_latency_ms_count Tool calls with a measured latency.",
            "# TYPE bonnet_gateway_tool_latency_ms_count counter",
        ]
        for (tool, ten) in sorted(_latency):
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
        for (tool, ten) in pairs:
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
            "otel_logging_bridge": _otel_ready,
        }
