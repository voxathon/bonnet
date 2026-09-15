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

"""Gateway telemetry: built-in RED counters, Prometheus text, OTel hooks."""

import pytest

from bonnet.core import telemetry
from bonnet.gateway import gateway_config


@pytest.fixture(autouse=True)
def clean():
    telemetry.reset_for_tests()
    telemetry.init_telemetry(enabled=True)
    yield
    telemetry.reset_for_tests()
    telemetry.init_telemetry(enabled=True)


def test_counts_group_by_tool_tenant_and_outcome():
    telemetry.observe_tool_call("publish", ok=True, tenant="alice")
    telemetry.observe_tool_call("publish", ok=True, tenant="alice")
    telemetry.observe_tool_call("publish", ok=False, tenant="alice")
    telemetry.observe_tool_call("connect", ok=True, tenant="bob")

    body = telemetry.render_prometheus()
    assert 'bonnet_gateway_tool_calls_total{tool="publish",tenant="alice",ok="true"} 2' in body
    assert 'bonnet_gateway_tool_calls_total{tool="publish",tenant="alice",ok="false"} 1' in body
    assert 'bonnet_gateway_tool_calls_total{tool="connect",tenant="bob",ok="true"} 1' in body


def test_latency_histogram_is_cumulative_and_complete():
    telemetry.observe_tool_call("publish", ok=True, tenant="a", duration_ms=3.0)
    telemetry.observe_tool_call("publish", ok=True, tenant="a", duration_ms=120.0)

    body = telemetry.render_prometheus()
    # Cumulative: both observations fall in le="1000" and le="+Inf".
    assert 'bonnet_gateway_tool_latency_ms_bucket{tool="publish",tenant="a",le="1000"} 2' in body
    assert 'bonnet_gateway_tool_latency_ms_bucket{tool="publish",tenant="a",le="+Inf"} 2' in body
    # Only the 3ms observation falls in le="5".
    assert 'bonnet_gateway_tool_latency_ms_bucket{tool="publish",tenant="a",le="5"} 1' in body
    assert 'bonnet_gateway_tool_latency_ms_count{tool="publish",tenant="a"} 2' in body


def test_disabled_mode_records_nothing():
    telemetry.init_telemetry(enabled=False)
    telemetry.observe_tool_call("publish", ok=True, tenant="a", duration_ms=5.0)

    body = telemetry.render_prometheus()
    assert "bonnet_gateway_tool_calls_total" not in body.replace(
        "# HELP bonnet_gateway_tool_calls_total Gateway MCP tool calls by tool, tenant and outcome.",
        "",
    ).replace(
        "# TYPE bonnet_gateway_tool_calls_total counter",
        "",
    )
    assert "bonnet_gateway_up 1" in body


def test_tool_span_is_transparent_without_sdk():
    # Without the OTel SDK configured the span is a NonRecordingSpan (or
    # None): recording nothing. Critically, body exceptions must propagate
    # (never swallowed into a second yield — that corrupts @contextmanager
    # middleware protocols, see test_gateway_auth forbidden-tool test).
    with telemetry.tool_span("publish", tenant="a") as span:
        assert span is None or not span.is_recording()
    with pytest.raises(RuntimeError, match="boom"):
        with telemetry.tool_span("publish"):
            raise RuntimeError("boom")


def test_tenant_labels_are_bounded():
    telemetry.observe_tool_call("publish", ok=True, tenant="x" * 200)
    snap = telemetry.snapshot()
    assert any(k.split("|")[1] == "x" * 32 for k in snap["calls"])


def test_gateway_toml_accepts_telemetry_keys(tmp_path):
    path = tmp_path / "gateway.toml"
    path.write_text(
        "[gateway]\nmetrics_enabled = false\notel_enabled = true\n", encoding="utf-8"
    )
    cfg = gateway_config.load(str(path))
    assert cfg is not None
    assert cfg.metrics_enabled is False
    assert cfg.otel_enabled is True
    gateway_config.validate(cfg)


def test_gateway_toml_rejects_non_bool_telemetry_keys():
    cfg = gateway_config.GatewayConfig(metrics_enabled="yes")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="metrics_enabled"):
        gateway_config.validate(cfg)
