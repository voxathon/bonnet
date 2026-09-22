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
into in-memory structures; ``observe_auth`` / ``observe_gating_refusal`` /
``observe_tool_error`` / ``observe_http`` classify *why* traffic looks the
way it does; ``in_flight`` tracks current saturation; ``render_prometheus``
exposes it all in Prometheus text exposition format for the gateway's
``/metrics`` route.

Per-call detail lives in the on-file log (``bonnet.core.logging`` via
``tools._gw_log`` and the middleware start/finish lines) — this module
carries only aggregates. Label values are bounded and never free text:
tenant ids are truncated, error types are exception class names, and
board/origin/argument values stay in the file log where they belong.
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
# status ("ok" | "absent" | "rejected") -> count
_auth: dict[str, int] = {}
# (tool, tenant, reason) -> count, reason in {"anonymous", "needs", "unknown"}
_gating: dict[tuple[str, str, str], int] = {}
# (tool, tenant, err) -> count, err is an exception class name
_errors: dict[tuple[str, str, str], int] = {}
# (route, method, ok) -> count, e.g. ("admin_tenant_add", "POST", "true")
_http: dict[tuple[str, str, str], int] = {}
# Currently executing tool calls (gauge) + high-water mark.
_in_flight = 0
_in_flight_peak = 0


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


def _norm_label(value: Any, *, max_len: int = 32) -> str:
    """Bounded label value for a closed set (status, reason, err, route)."""
    try:
        s = str(value or "unknown")
    except Exception:
        s = "unknown"
    return (s.strip() or "unknown")[:max_len]


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
    global _in_flight, _in_flight_peak
    with _lock:
        _calls.clear()
        _latency.clear()
        _buckets.clear()
        _auth.clear()
        _gating.clear()
        _errors.clear()
        _http.clear()
        _in_flight = 0
        _in_flight_peak = 0


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


def observe_auth(status: str) -> None:
    """Record one auth resolution (ok/absent/rejected). Never raises."""
    try:
        if not _enabled:
            return
        key = _norm_label(status, max_len=16)
        with _lock:
            _auth[key] = _auth.get(key, 0) + 1
    except Exception:
        pass


def observe_gating_refusal(op: str, *, tenant: str = "", reason: str = "unknown") -> None:
    """Record one call refused by gating before running. Never raises.

    ``reason`` is a bounded class — "anonymous" (anonymous tenant forbids
    the tool) or "needs" (identity/board PERMISSIONS unmet) — never the
    free-text explanation shown to the caller.
    """
    try:
        if not _enabled:
            return
        tool = _norm_tool(op)
        ten = _norm_tenant(tenant)
        kind = _norm_label(reason, max_len=16)
        if kind not in ("anonymous", "needs"):
            kind = "unknown"
        with _lock:
            key = (tool, ten, kind)
            _gating[key] = _gating.get(key, 0) + 1
    except Exception:
        pass


def observe_tool_error(op: str, *, tenant: str = "", err: str = "") -> None:
    """Record one failed tool call by error type. Never raises.

    ``err`` is an exception class name (``type(e).__name__``), a naturally
    bounded set — never a message, board name, or origin.
    """
    try:
        if not _enabled:
            return
        tool = _norm_tool(op)
        ten = _norm_tenant(tenant)
        kind = _norm_label(err, max_len=64)
        with _lock:
            key = (tool, ten, kind)
            _errors[key] = _errors.get(key, 0) + 1
    except Exception:
        pass


def observe_http(route: str, method: str, *, ok: bool = True) -> None:
    """Record one non-tool HTTP hit (health, facade, admin...). Never raises.

    ``route`` is a fixed operator-known string per handler (e.g.
    "admin_tenant_add"), never a raw path — path params would mint
    unbounded series.
    """
    try:
        if not _enabled:
            return
        rt = _norm_label(route, max_len=64)
        meth = _norm_label(method, max_len=8).upper()
        ok_s = "true" if ok else "false"
        with _lock:
            key = (rt, meth, ok_s)
            _http[key] = _http.get(key, 0) + 1
    except Exception:
        pass


@contextlib.contextmanager
def in_flight() -> Iterator[None]:
    """Track one in-flight tool call for the saturation gauge.

    Best-effort and never raises on entry or exit; the ``yield`` is never
    wrapped in a catching ``except`` so body exceptions propagate cleanly.
    """
    global _in_flight, _in_flight_peak
    tracked = False
    try:
        if _enabled:
            with _lock:
                _in_flight += 1
                if _in_flight > _in_flight_peak:
                    _in_flight_peak = _in_flight
            tracked = True
    except Exception:
        tracked = False
    try:
        yield
    finally:
        if tracked:
            try:
                with _lock:
                    _in_flight -= 1
            except Exception:
                pass


def _esc(s: str) -> str:
    return s.replace("\\", r"\\").replace('"', r"\"").replace("\n", r"\n")


def render_prometheus(*, tenant_count: int | None = None) -> str:
    """Render built-in counters in Prometheus text exposition format.

    ``tenant_count`` is read live by the ``/metrics`` handler (registered
    tenants, not active connections) and rendered as a gauge; ``None``
    omits the series. When disabled, only the ``up`` gauge is reported.
    """
    if not _enabled:
        return (
            "# HELP bonnet_gateway_up 1 while the gateway metrics endpoint serves.\n"
            "# TYPE bonnet_gateway_up gauge\n"
            "bonnet_gateway_up 1\n"
        )
    lines = [
        "# HELP bonnet_gateway_up 1 while the gateway metrics endpoint serves.",
        "# TYPE bonnet_gateway_up gauge",
        "bonnet_gateway_up 1",
        "# HELP bonnet_gateway_uptime_s Seconds since the gateway process started.",
        "# TYPE bonnet_gateway_uptime_s gauge",
        f"bonnet_gateway_uptime_s {time.time() - _start_time:.1f}",
        "# HELP bonnet_gateway_in_flight Tool calls currently executing.",
        "# TYPE bonnet_gateway_in_flight gauge",
        f"bonnet_gateway_in_flight {_in_flight}",
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
            "# HELP bonnet_gateway_auth_total Gateway auth resolutions by outcome.",
            "# TYPE bonnet_gateway_auth_total counter",
        ]
        for status in sorted(_auth):
            lines.append(f'bonnet_gateway_auth_total{{status="{_esc(status)}"}} {_auth[status]}')
        lines += [
            "# HELP bonnet_gateway_gating_refusals_total Tool calls refused by gating before running.",
            "# TYPE bonnet_gateway_gating_refusals_total counter",
        ]
        for tool, ten, reason in sorted(_gating):
            lines.append(
                f'bonnet_gateway_gating_refusals_total{{tool="{_esc(tool)}",'
                f'tenant="{_esc(ten)}",reason="{_esc(reason)}"}} {_gating[(tool, ten, reason)]}'
            )
        lines += [
            "# HELP bonnet_gateway_tool_errors_total Failed tool calls by error type.",
            "# TYPE bonnet_gateway_tool_errors_total counter",
        ]
        for tool, ten, err in sorted(_errors):
            lines.append(
                f'bonnet_gateway_tool_errors_total{{tool="{_esc(tool)}",'
                f'tenant="{_esc(ten)}",err="{_esc(err)}"}} {_errors[(tool, ten, err)]}'
            )
        lines += [
            "# HELP bonnet_gateway_http_total Non-tool HTTP hits by route, method and outcome.",
            "# TYPE bonnet_gateway_http_total counter",
        ]
        for route, method, ok_s in sorted(_http):
            lines.append(
                f'bonnet_gateway_http_total{{route="{_esc(route)}",'
                f'method="{_esc(method)}",ok="{ok_s}"}} {_http[(route, method, ok_s)]}'
            )
        if tenant_count is not None:
            lines += [
                "# HELP bonnet_gateway_tenants Registered tenants (read at scrape time).",
                "# TYPE bonnet_gateway_tenants gauge",
                f"bonnet_gateway_tenants {int(tenant_count)}",
            ]
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
            "auth": dict(_auth),
            "gating_refusals": {f"{t}|{ten}|{r}": n for (t, ten, r), n in _gating.items()},
            "errors": {f"{t}|{ten}|{e}": n for (t, ten, e), n in _errors.items()},
            "http": {f"{rt}|{m}|{ok_s}": n for (rt, m, ok_s), n in _http.items()},
            "in_flight": _in_flight,
            "in_flight_peak": _in_flight_peak,
        }
