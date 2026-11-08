"""Isolate Studio modules by namespace; only gated decision outputs reach acr.

This lexer locates the package declaration and rejects external data references.
It does not parse or rewrite rule bodies: OPA remains the Rego parser/compiler.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator

from acr.policy_studio.core_bundle import validate_extension


def _tokens(source: str) -> Iterator[tuple[str, int, int]]:
    index = 0
    while index < len(source):
        start = index
        char = source[index]
        if char.isspace():
            index += 1
        elif char == "#":
            end = source.find("\n", index)
            index = len(source) if end < 0 else end + 1
        elif char in ('"', "`"):
            delimiter = char
            index += 1
            while index < len(source):
                if delimiter == '"' and source[index] == "\\":
                    index += 2
                elif source[index] == delimiter:
                    index += 1
                    yield ("<string>", start, index)
                    break
                else:
                    index += 1
            else:
                raise ValueError("Unterminated string in Studio policy")
        elif char.isalpha() or char == "_":
            index += 1
            while index < len(source) and (source[index].isalnum() or source[index] == "_"):
                index += 1
            yield (source[start:index], start, index)
        else:
            index += 1
            yield (char, start, index)


def _package_span(source: str) -> tuple[int, int]:
    tokens = list(_tokens(source))
    if len(tokens) < 2 or tokens[0][0] != "package" or tokens[1][0] != "acr":
        raise ValueError("Studio policies must declare exactly package acr")
    if len(tokens) > 2 and tokens[2][0] in {".", "["}:
        raise ValueError("Studio policies must declare exactly package acr")
    if (
        sum(
            token[0] == "package" and (index == 0 or tokens[index - 1][0] != ".")
            for index, token in enumerate(tokens)
        )
        != 1
    ):
        raise ValueError("Studio policy must contain exactly one package declaration")
    if any(
        token[0] == "data" and (index == 0 or tokens[index - 1][0] != ".")
        for index, token in enumerate(tokens)
    ):
        raise ValueError(
            "Studio policies cannot reference data or import data; use input and module-local "
            "helpers, or explicitly deploy a reviewed global operator extension"
        )
    return tokens[1][1], tokens[1][2]


def validate_studio_policy(source: str, *, name: str) -> None:
    validate_extension(source, name=name)
    _package_span(source)


def isolate_studio_policy(*, agent_id: str, source: str) -> tuple[str, str]:
    validate_studio_policy(source, name=agent_id)
    start, end = _package_span(source)
    namespace = "acr_studio.agent_" + hashlib.sha256(agent_id.encode()).hexdigest()
    isolated = source[:start] + namespace + source[end:]
    guard = f"input.agent.agent_id == {json.dumps(agent_id)}"
    reference = f"data.{namespace}"
    bridge = ["package acr", "import future.keywords.if", "import future.keywords.contains"]

    def invalid(output: str, condition: str) -> None:
        reason = json.dumps(f"Invalid Studio output: {output}")
        bridge.append(f"deny contains {reason} if {{ {guard}; {condition} }}")

    for collection in ("is_array", "is_set"):
        bridge.append(
            f"deny contains reason if {{ {guard}; reasons := {reference}.deny; "
            f"{collection}(reasons); reason := reasons[_]; is_string(reason) }}"
        )
    invalid("deny", f"value := {reference}.deny; not is_array(value); not is_set(value)")
    invalid(
        "deny element", f"reasons := {reference}.deny; value := reasons[_]; not is_string(value)"
    )
    for output in ("allow", "modify", "escalate"):
        invalid(output, f"value := {reference}.{output}; not is_boolean(value)")
    # Explicit false is a restriction; true cannot override core allow conditions.
    bridge.append(
        f'deny contains "Studio policy explicitly disallows action" if {{ {guard}; {reference}.allow == false }}'
    )
    for output in ("modify", "escalate"):
        bridge.append(f"{output} if {{ {guard}; {reference}.{output} == true }}")
    metadata = {
        "modified_action": ("modify", "is_object"),
        "modified_parameters": ("modify", "is_object"),
        "escalate_queue": ("escalate", "is_string"),
        "escalate_sla_minutes": ("escalate", "is_number"),
    }
    for output, (effect, check) in metadata.items():
        condition = f"{reference}.{effect} == true; value := {reference}.{output}"
        bridge.append(f"{output} := value if {{ {guard}; {condition}; {check}(value) }}")
        invalid(output, f"{condition}; not {check}(value)")
    invalid(
        "escalate_sla_minutes",
        f"{reference}.escalate == true; value := {reference}.escalate_sla_minutes; is_number(value); value <= 0",
    )
    invalid(
        "escalate_sla_minutes",
        f"{reference}.escalate == true; value := {reference}.escalate_sla_minutes; is_number(value); value != floor(value)",
    )
    return isolated, "\n".join(bridge) + "\n"
