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

"""Gateway metrics: built-in RED counters + Prometheus text."""

import pytest

from bonnet.core import metrics
from bonnet.gateway import gateway_config


@pytest.fixture(autouse=True)
def clean():
    metrics.reset_for_tests()
    metrics.init_metrics(enabled=True)
    yield
    metrics.reset_for_tests()
    metrics.init_metrics(enabled=True)


def test_counts_group_by_tool_tenant_and_outcome():
    metrics.observe_tool_call("publish", ok=True, tenant="alice")
    metrics.observe_tool_call("publish", ok=True, tenant="alice")
    metrics.observe_tool_call("publish", ok=False, tenant="alice")
    metrics.observe_tool_call("connect", ok=True, tenant="bob")

    body = metrics.render_prometheus()
    assert 'bonnet_gateway_tool_calls_total{tool="publish",tenant="alice",ok="true"} 2' in body
    assert 'bonnet_gateway_tool_calls_total{tool="publish",tenant="alice",ok="false"} 1' in body
    assert 'bonnet_gateway_tool_calls_total{tool="connect",tenant="bob",ok="true"} 1' in body


def test_latency_histogram_is_cumulative_and_complete():
    metrics.observe_tool_call("publish", ok=True, tenant="a", duration_ms=3.0)
    metrics.observe_tool_call("publish", ok=True, tenant="a", duration_ms=120.0)

    body = metrics.render_prometheus()
    # Cumulative: both observations fall in le="1000" and le="+Inf".
    assert 'bonnet_gateway_tool_latency_ms_bucket{tool="publish",tenant="a",le="1000"} 2' in body
    assert 'bonnet_gateway_tool_latency_ms_bucket{tool="publish",tenant="a",le="+Inf"} 2' in body
    # Only the 3ms observation falls in le="5".
    assert 'bonnet_gateway_tool_latency_ms_bucket{tool="publish",tenant="a",le="5"} 1' in body
    assert 'bonnet_gateway_tool_latency_ms_count{tool="publish",tenant="a"} 2' in body


def test_disabled_mode_records_nothing():
    metrics.init_metrics(enabled=False)
    metrics.observe_tool_call("publish", ok=True, tenant="a", duration_ms=5.0)
    metrics.observe_auth("ok")
    metrics.observe_gating_refusal("publish", tenant="a", reason="needs")
    metrics.observe_tool_error("publish", tenant="a", err="ValueError")
    metrics.observe_http("health", "GET", ok=True)
    with metrics.in_flight():
        pass

    body = metrics.render_prometheus()
    assert "bonnet_gateway_tool_calls_total" not in body.replace(
        "# HELP bonnet_gateway_tool_calls_total Gateway MCP tool calls by tool, tenant and outcome.",
        "",
    ).replace(
        "# TYPE bonnet_gateway_tool_calls_total counter",
        "",
    )
    assert "bonnet_gateway_auth_total" not in body
    assert "bonnet_gateway_gating_refusals_total" not in body
    assert "bonnet_gateway_tool_errors_total" not in body
    assert "bonnet_gateway_http_total" not in body
    assert "bonnet_gateway_up 1" in body


def test_tenant_labels_are_bounded():
    metrics.observe_tool_call("publish", ok=True, tenant="x" * 200)
    snap = metrics.snapshot()
    assert any(k.split("|")[1] == "x" * 32 for k in snap["calls"])


def test_gateway_toml_accepts_metrics_key(tmp_path):
    path = tmp_path / "gateway.toml"
    path.write_text(
        "[gateway]\nmetrics_enabled = false\n",
        encoding="utf-8",
    )
    cfg = gateway_config.load(str(path))
    assert cfg is not None
    assert cfg.metrics_enabled is False
    gateway_config.validate(cfg)


def test_gateway_toml_rejects_non_bool_metrics_key():
    cfg = gateway_config.GatewayConfig(metrics_enabled="yes")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="metrics_enabled"):
        gateway_config.validate(cfg)


def test_auth_outcomes_are_counted_by_status():
    metrics.observe_auth("ok")
    metrics.observe_auth("absent")
    metrics.observe_auth("rejected")
    metrics.observe_auth("rejected")

    body = metrics.render_prometheus()
    assert 'bonnet_gateway_auth_total{status="ok"} 1' in body
    assert 'bonnet_gateway_auth_total{status="absent"} 1' in body
    assert 'bonnet_gateway_auth_total{status="rejected"} 2' in body


def test_gating_refusals_split_anonymous_from_needs():
    metrics.observe_gating_refusal("publish", tenant="a", reason="anonymous")
    metrics.observe_gating_refusal("publish", tenant="a", reason="needs")
    metrics.observe_gating_refusal("connect", tenant="b", reason="needs")

    body = metrics.render_prometheus()
    assert (
        'bonnet_gateway_gating_refusals_total{tool="publish",tenant="a",reason="anonymous"} 1'
        in body
    )
    assert (
        'bonnet_gateway_gating_refusals_total{tool="publish",tenant="a",reason="needs"} 1'
        in body
    )
    assert (
        'bonnet_gateway_gating_refusals_total{tool="connect",tenant="b",reason="needs"} 1'
        in body
    )


def test_gating_refusal_rejects_free_text_reasons():
    # Only the bounded classes survive; anything else folds to "unknown"
    # rather than minting a series per refusal message.
    metrics.observe_gating_refusal("publish", tenant="a", reason="board is closed, ask bob")

    body = metrics.render_prometheus()
    assert 'reason="unknown"' in body
    assert "ask bob" not in body


def test_tool_errors_group_by_type():
    metrics.observe_tool_error("publish", tenant="a", err="FirehoseClientError")
    metrics.observe_tool_error("publish", tenant="a", err="FirehoseClientError")
    metrics.observe_tool_error("connect", tenant="a", err="ValueError")

    body = metrics.render_prometheus()
    assert (
        'bonnet_gateway_tool_errors_total{tool="publish",tenant="a",err="FirehoseClientError"} 2'
        in body
    )
    assert (
        'bonnet_gateway_tool_errors_total{tool="connect",tenant="a",err="ValueError"} 1'
        in body
    )


def test_http_hits_group_by_route_method_and_outcome():
    metrics.observe_http("health", "GET", ok=True)
    metrics.observe_http("admin_tenant_add", "POST", ok=True)
    metrics.observe_http("admin_tenant_add", "POST", ok=False)

    body = metrics.render_prometheus()
    assert 'bonnet_gateway_http_total{route="health",method="GET",ok="true"} 1' in body
    assert 'bonnet_gateway_http_total{route="admin_tenant_add",method="POST",ok="true"} 1' in body
    assert 'bonnet_gateway_http_total{route="admin_tenant_add",method="POST",ok="false"} 1' in body


def test_in_flight_gauge_tracks_and_returns_to_zero():
    with metrics.in_flight():
        with metrics.in_flight():
            assert metrics.snapshot()["in_flight"] == 2
            body = metrics.render_prometheus()
            assert "bonnet_gateway_in_flight 2" in body
        assert metrics.snapshot()["in_flight"] == 1
    snap = metrics.snapshot()
    assert snap["in_flight"] == 0
    assert snap["in_flight_peak"] == 2


def test_in_flight_releases_on_exception():
    with pytest.raises(RuntimeError, match="boom"):
        with metrics.in_flight():
            raise RuntimeError("boom")
    assert metrics.snapshot()["in_flight"] == 0


def test_uptime_and_tenant_gauges_render():
    body = metrics.render_prometheus(tenant_count=3)
    assert "bonnet_gateway_uptime_s" in body
    assert "bonnet_gateway_tenants 3" in body
    # Tenant count is scrape-time: omitted when unknown.
    assert "bonnet_gateway_tenants" not in metrics.render_prometheus()
