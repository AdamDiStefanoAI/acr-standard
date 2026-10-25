"""Bounded, offline regressions for the patched W3C trace-context parser."""

from opentelemetry.trace import get_current_span
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator


def test_trace_context_preserves_valid_trace_and_state():
    context = TraceContextTextMapPropagator().extract(
        {
            "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "tracestate": "vendor=value,other=second",
        }
    )
    span_context = get_current_span(context).get_span_context()
    assert span_context.is_valid
    assert span_context.trace_id == int("0af7651916cd43dd8448eb211c80319c", 16)
    assert list(span_context.trace_state.items()) == [("vendor", "value"), ("other", "second")]


def test_trace_state_rejects_combined_headers_over_security_limit():
    # Each member is individually valid, and the 32-member limit is respected.
    # The combined header is just over the patched 8192-character limit. This
    # tests bounded rejection without a timing assertion or a large CPU payload.
    members = [f"k{index:02d}=" + "x" * 253 for index in range(32)]
    header = ",".join(members)
    assert len(header) == 8255
    context = TraceContextTextMapPropagator().extract(
        {
            "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "tracestate": header,
        }
    )
    span_context = get_current_span(context).get_span_context()
    assert span_context.is_valid
    assert list(span_context.trace_state.items()) == []
