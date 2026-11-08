#!/usr/bin/env python3
"""Disposable Docker/Kind release-upgrade contract test. Never target production."""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

OUT = Path("managed-policy-evidence")
OUT.mkdir(exist_ok=True)
OPERATOR = {"X-Operator-API-Key": "ci-operator-only"}
BASE = "http://127.0.0.1:8000"
_agent_access_tokens: dict[str, str] = {}
http = urllib.request.build_opener(urllib.request.ProxyHandler({}))
MANIFEST = {
    "agent_id": "upgrade-ci",
    "owner": "synthetic@example.invalid",
    "purpose": "Disposable upgrade validation",
    "risk_tier": "medium",
    "allowed_tools": ["query_customer_db"],
    "forbidden_tools": [],
    "boundaries": {"max_actions_per_minute": 10000, "max_cost_per_hour_usd": 100},
}


def run(*args, **kw):
    return subprocess.run(args, check=True, text=True, **kw)


def request(method, path, body=None, headers=None):
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        response = http.open(req, timeout=5)
    except urllib.error.HTTPError as exc:
        response = exc
    raw = response.read()
    try:
        value = json.loads(raw)
    except ValueError:
        value = raw
    return response.status, value


def wait_ready():
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            if request("GET", "/acr/ready")[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(2)
    raise AssertionError("Gateway did not become ready")


def agent_token(agent_id="upgrade-ci", *, refresh=False):
    """Reuse the legitimate issued token across probes and release changes."""
    if agent_id not in _agent_access_tokens or refresh:
        status, token = request("POST", f"/acr/agents/{agent_id}/token", {}, OPERATOR)
        assert status == 200, token
        _agent_access_tokens[agent_id] = token["access_token"]
    return _agent_access_tokens[agent_id]


def evaluate(parameters, agent_id="upgrade-ci"):
    body = {
        "agent_id": agent_id,
        "action": {"tool_name": "query_customer_db", "parameters": parameters},
    }
    response = request(
        "POST", "/acr/evaluate", body, {"Authorization": "Bearer " + agent_token(agent_id)}
    )
    # A denied policy decision (403), stale core, or unavailable dependency must
    # never mint a new token. Retry only an actual authentication failure, once.
    if response[0] == 401:
        response = request(
            "POST",
            "/acr/evaluate",
            body,
            {"Authorization": "Bearer " + agent_token(agent_id, refresh=True)},
        )
    return response


STUDIO_POLICY_A = """package acr
import future.keywords.if
import future.keywords.contains
trigger := input.action.parameters.studio_sentinel
deny contains "Studio sentinel" if { trigger == true }
modify := true if { input.action.parameters.studio_modify == true }
modified_parameters := {"customer_id": "reviewed"} if { input.action.parameters.studio_modify == true }
escalate := true if { input.action.parameters.studio_escalate == true }
escalate_queue := "studio-ci" if { input.action.parameters.studio_escalate == true }
"""
# Existing v1 syntax without imports must receive its own manifest dialect entry.
STUDIO_POLICY_B = """package acr
trigger := input.action.parameters.agent_b_only
deny contains "Agent B sentinel" if { trigger == true }
"""


def assert_policy(label):
    wait_ready()
    observed = []
    for agent_id in ("upgrade-ci", "upgrade-ci-b"):
        for parameters, expected in [
            ({"customer_id": "C-12345"}, "allow"),
            ({"migration_sentinel": True}, "deny"),
            ({"legacy_v0_sentinel": True}, "deny"),
            ({"studio_sentinel": True}, "deny" if agent_id == "upgrade-ci" else "allow"),
            ({"studio_modify": True}, "modify" if agent_id == "upgrade-ci" else "allow"),
            ({"studio_escalate": True}, "escalate" if agent_id == "upgrade-ci" else "allow"),
            ({"agent_b_only": True}, "deny" if agent_id == "upgrade-ci-b" else "allow"),
        ]:
            status, result = evaluate(parameters, agent_id)
            assert result.get("decision") == expected, (label, agent_id, parameters, status, result)
            assert status == {"allow": 200, "deny": 403, "modify": 200, "escalate": 202}[expected]
            if expected == "modify":
                assert result["modified_action"]["parameters"] == {"customer_id": "reviewed"}
            if expected == "escalate":
                assert result.get("approval_request_id"), result
            observed.append({"agent_id": agent_id, "parameters": parameters, "decision": expected})
    status, archive = request("GET", "/acr/policy-bundles/active.tar.gz", headers=OPERATOR)
    assert status == 200
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        sources = "\n".join(
            bundle.extractfile(n).read().decode() for n in bundle.getnames() if n.endswith(".rego")
        )
    assert all(
        marker in sources
        for marker in (
            "migration_sentinel",
            "legacy_v0_sentinel",
            "studio_sentinel",
            "agent_b_only",
        )
    )
    OUT.joinpath(label + ".txt").write_text(
        "PASS: readiness, core match, legacy v0 deny, local policy, two-agent Studio DENY/MODIFY/ESCALATE isolation\n"
    )
    OUT.joinpath(label + "-decisions.json").write_text(json.dumps(observed, indent=2) + "\n")


def publish_policy(agent_id, policy):
    manifest = {**MANIFEST, "agent_id": agent_id}
    status, body = request("POST", "/acr/agents", manifest, OPERATOR)
    assert status == 201, (status, body)
    status, draft = request(
        "POST",
        "/acr/policy-drafts",
        {
            "name": "Persistent isolation sentinel " + agent_id,
            "agent_id": agent_id,
            "template": "customer_support",
            "manifest": manifest,
            "rego_policy": policy,
            "wizard_inputs": {},
        },
        OPERATOR,
    )
    assert status == 201, (status, draft)
    status, release = request(
        "POST",
        "/acr/policy-drafts/" + draft["draft_id"] + "/publish",
        {"notes": "Synthetic CI only"},
        OPERATOR,
    )
    assert status == 201, (status, release)
    status, body = request(
        "POST", "/acr/policy-drafts/releases/" + release["release_id"] + "/activate", {}, OPERATOR
    )
    assert status == 200, (status, body)


def seed():
    wait_ready()
    publish_policy("upgrade-ci", STUDIO_POLICY_A)
    publish_policy("upgrade-ci-b", STUDIO_POLICY_B)
    # Activation propagation is asynchronous. Check actual decisions, not readiness alone.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        first = evaluate({"studio_sentinel": True})[1]
        second = evaluate({"agent_b_only": True}, "upgrade-ci-b")[1]
        if first.get("decision") == second.get("decision") == "deny":
            return
        time.sleep(2)
    raise AssertionError("Both Studio policies did not propagate")


def direct_opa_probe():
    """The same unmocked OPA response checks run in Docker and every kind gateway Pod."""
    return """
import json
import os
import urllib.request
manifest = {"allowed_tools": ["query_customer_db"], "forbidden_tools": [], "boundaries": {"max_actions_per_minute": 10000, "max_cost_per_hour_usd": 100}}
observed = []
for agent in ("upgrade-ci", "upgrade-ci-b"):
    for flag in ("legacy_v0_sentinel", "studio_sentinel", "studio_modify", "studio_escalate", "agent_b_only"):
        payload = {"input": {"agent": {**manifest, "agent_id": agent}, "action": {"tool_name": "query_customer_db", "parameters": {flag: True}}, "context": {"actions_this_minute": 0, "hourly_spend_usd": 0}}}
        req = urllib.request.Request(os.environ["OPA_URL"] + "/v1/data/acr", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as response:
            result = json.load(response)["result"]
        deny = result.get("deny", [])
        if flag == "legacy_v0_sentinel":
            assert "Legacy v0 sentinel" in deny, (agent, flag, result)
        elif flag == "studio_sentinel" and agent == "upgrade-ci":
            assert "Studio sentinel" in deny, (agent, flag, result)
        elif flag == "agent_b_only" and agent == "upgrade-ci-b":
            assert "Agent B sentinel" in deny, (agent, flag, result)
        elif flag == "studio_modify" and agent == "upgrade-ci":
            assert result.get("modify") is True and result.get("modified_parameters") == {"customer_id": "reviewed"}, result
        elif flag == "studio_escalate" and agent == "upgrade-ci":
            assert result.get("escalate") is True and result.get("escalate_queue") == "studio-ci", result
        else:
            assert not deny and result.get("allow") is True, (agent, flag, result)
            assert not result.get("modify") and not result.get("escalate"), result
            assert result.get("modified_parameters") is None, result
            assert result.get("escalate_queue", "default") == "default", result
        observed.append({"agent_id": agent, "flag": flag, "deny": deny, "modify": result.get("modify", False), "escalate": result.get("escalate", False)})
print(json.dumps(observed, sort_keys=True))
"""


def docker_opa_check(label):
    result = compose(
        "exec", "-T", "acr-gateway", "python", "-c", direct_opa_probe(), capture_output=True
    )
    OUT.joinpath(label + "-opa.json").write_text(result.stdout)


def compose(*args, **kwargs):
    assert os.environ["COMPOSE_PROJECT_NAME"].startswith("acr-managed-")
    return run("docker", "compose", *args, **kwargs)


def candidate_preflight(label):
    status, before = request("GET", "/acr/policy-drafts/releases/history", headers=OPERATOR)
    assert status == 200, before
    result = compose(
        "run",
        "--rm",
        "--no-deps",
        "--entrypoint",
        "python",
        "acr-gateway",
        "-m",
        "acr.policy_studio.distribution",
        "preflight",
        "--extensions",
        "/operator-policies",
        capture_output=True,
    )
    status, after = request("GET", "/acr/policy-drafts/releases/history", headers=OPERATOR)
    assert status == 200 and after == before, "Candidate preflight changed stored releases"
    OUT.joinpath(label + "-preflight.json").write_text(result.stdout)


def docker_test():
    compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180")
    seed()
    assert_policy("docker-before")
    docker_opa_check("docker-before")
    # Deliberately upgrade gateway alone: its pinned core must refuse old loaded OPA.
    os.environ["ACR_GATEWAY_IMAGE"] = "acr-gateway:upgrade-ci-next"
    candidate_preflight("docker-upgrade")
    compose("up", "-d", "--no-build", "--no-deps", "--force-recreate", "acr-gateway")
    time.sleep(8)
    assert request("GET", "/acr/ready")[0] == 503
    status, result = evaluate({"customer_id": "C-12345"})
    assert status != 200 and result.get("decision") != "allow", (status, result)
    OUT.joinpath("docker-mismatch.txt").write_text("PASS: stale OPA never authorizes new gateway\n")
    # Explicit intentional coordinated policy update, then restart OPA to reload its config.
    compose("run", "--rm", "--no-deps", "acr-policy-export")
    compose("up", "-d", "--no-deps", "--force-recreate", "opa")
    assert_policy("docker-upgrade")
    docker_opa_check("docker-upgrade")
    os.environ["ACR_GATEWAY_IMAGE"] = "acr-gateway:upgrade-ci-old"
    candidate_preflight("docker-rollback")
    compose("run", "--rm", "--no-deps", "acr-policy-export")
    compose("up", "-d", "--no-build", "--no-deps", "--force-recreate", "acr-gateway", "opa")
    assert_policy("docker-rollback")
    docker_opa_check("docker-rollback")


def kubectl(*args, **kw):
    return run("kubectl", "--context", "kind-acr-managed-ci", *args, **kw)


def validate_kind_killswitch(label):
    """Require the real Pod and service, then exercise a synthetic agent kill/restore."""
    kubectl("-n", "acr-system", "rollout", "status", "deployment/acr-killswitch", "--timeout=240s")
    kubectl(
        "-n",
        "acr-system",
        "wait",
        "--for=condition=Ready",
        "pod",
        "-l",
        "app=acr-killswitch",
        "--timeout=120s",
    )
    probe = """
import json
import os
import urllib.request
base = "http://acr-killswitch:8443"
headers = {
    "Content-Type": "application/json",
    "X-Killswitch-Secret": os.environ["KILLSWITCH_SECRET"],
    "X-Operator-API-Key": os.environ["SERVICE_OPERATOR_API_KEY"],
}
agent = "managed-killswitch-ci"
def call(path, body=None):
    request = urllib.request.Request(
        base + path, data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        assert response.status == 200
        return json.load(response)
assert call("/health")["status"] == "healthy"
assert call("/ready")["status"] == "healthy"
try:
    assert call("/acr/kill", {"agent_id": agent, "reason": "Disposable kind validation"})["is_killed"] is True
    assert call("/acr/kill/status/" + agent)["is_killed"] is True
finally:
    assert call("/acr/kill/restore", {"agent_id": agent})["is_killed"] is False
assert call("/acr/kill/status/" + agent)["is_killed"] is False
print("PASS: kill-switch ready, synthetic kill/status/restore")
"""
    result = kubectl(
        "-n",
        "acr-system",
        "exec",
        "deployment/acr-gateway",
        "-c",
        "gateway",
        "--",
        "python",
        "-c",
        probe,
        capture_output=True,
    )
    OUT.joinpath(label + "-killswitch.txt").write_text(result.stdout)
    print(result.stdout, end="")


def kind_test():
    # Render the actual supported base, replacing only disposable infrastructure/config.
    rendered = kubectl("kustomize", "deploy/k8s/base", capture_output=True).stdout
    docs = list(yaml.safe_load_all(rendered))
    docs = [
        d
        for d in docs
        if d["kind"]
        not in {"Ingress", "NetworkPolicy", "HorizontalPodAutoscaler", "PodDisruptionBudget"}
    ]
    for d in docs:
        if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "acr-gateway-config":
            d["data"] = {
                "ACR_ENV": "test",
                "SCHEMA_BOOTSTRAP_MODE": "validate",
                "OPA_URL": "http://127.0.0.1:8181",
                "POLICY_EXTENSION_DIR": "/operator-policies",
                "KILLSWITCH_URL": "http://acr-killswitch:8443",
                "REQUIRE_BUNDLE_AUTH": "true",
                "OIDC_ENABLED": "false",
                "EXECUTE_ALLOWED_ACTIONS": "false",
                "POLICY_BUNDLE_LOCAL_DIR": "/tmp/policy-bundles",
            }
        if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "acr-operator-policies":
            d["data"]["sentinel.rego"] = Path("operator-policies/sentinel.rego").read_text()
            d["data"]["legacy_v0.rego"] = Path("operator-policies/legacy_v0.rego").read_text()
        if d["kind"] == "Deployment":
            d["spec"]["replicas"] = 2 if d["metadata"]["name"] == "acr-gateway" else 1
            for c in (
                d["spec"]["template"]["spec"].get("initContainers", [])
                + d["spec"]["template"]["spec"]["containers"]
            ):
                if c["image"].startswith("acr-gateway:"):
                    c["image"] = "acr-gateway:upgrade-ci-old"
                if c["image"].startswith("acr-killswitch:"):
                    c["image"] = "acr-killswitch:upgrade-ci"
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "acr-gateway-secret", "namespace": "acr-system"},
        "stringData": {
            "DATABASE_URL": "postgresql+asyncpg://acr:acr_ci_password@postgres:5432/acr_control_plane",
            "REDIS_URL": "redis://redis:6379/0",
            "JWT_SECRET_KEY": os.environ["JWT_SECRET_KEY"],
            "KILLSWITCH_SECRET": os.environ["KILLSWITCH_SECRET"],
            "OPERATOR_API_KEYS_JSON": os.environ["OPERATOR_API_KEYS_JSON"],
            "SERVICE_OPERATOR_API_KEY": "ci-operator-only",
        },
    }
    docs.append(secret)
    for name, image, port, env in [
        (
            "postgres",
            "postgres:16-alpine",
            5432,
            {
                "POSTGRES_USER": "acr",
                "POSTGRES_PASSWORD": "acr_ci_password",
                "POSTGRES_DB": "acr_control_plane",
            },
        ),
        ("redis", "redis:7-alpine", 6379, {}),
    ]:
        docs += [
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": name, "namespace": "acr-system"},
                "spec": {
                    "replicas": 1,
                    "selector": {"matchLabels": {"app": name}},
                    "template": {
                        "metadata": {"labels": {"app": name}},
                        "spec": {
                            "containers": [
                                {
                                    "name": name,
                                    "image": image,
                                    "ports": [{"containerPort": port}],
                                    "env": [{"name": k, "value": v} for k, v in env.items()],
                                }
                            ]
                        },
                    },
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": name, "namespace": "acr-system"},
                "spec": {"selector": {"app": name}, "ports": [{"port": port, "targetPort": port}]},
            },
        ]
    manifest = OUT / "kind-test.yaml"
    manifest.write_text(yaml.safe_dump_all(docs, sort_keys=False))
    kubectl("apply", "-f", str(manifest))
    kubectl("-n", "acr-system", "rollout", "status", "deployment/acr-gateway", "--timeout=240s")

    # Service port-forward stays bound to one Pod and exits when that Pod rolls.
    def forward():
        return subprocess.Popen(
            [
                "kubectl",
                "--context",
                "kind-acr-managed-ci",
                "-n",
                "acr-system",
                "port-forward",
                "service/acr-gateway",
                "8000:8000",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    proc = forward()
    try:
        seed()
        assert_policy("kind-before")
        validate_kind_killswitch("kind-before")
        result = kubectl(
            "-n",
            "acr-system",
            "exec",
            "deployment/acr-gateway",
            "-c",
            "gateway",
            "--",
            "python",
            "-c",
            direct_opa_probe(),
            capture_output=True,
        )
        OUT.joinpath("kind-before-opa.json").write_text(result.stdout)
        for label, image in [
            ("kind-upgrade", "acr-gateway:upgrade-ci-next"),
            ("kind-rollback", "acr-gateway:upgrade-ci-old"),
        ]:
            proc.terminate()
            proc.wait(timeout=10)
            kubectl(
                "-n",
                "acr-system",
                "set",
                "image",
                "deployment/acr-gateway",
                f"gateway={image}",
                f"export-core-policy={image}",
                f"alembic-upgrade={image}",
            )
            kubectl(
                "-n", "acr-system", "rollout", "status", "deployment/acr-gateway", "--timeout=240s"
            )
            proc = forward()
            assert_policy(label)
            validate_kind_killswitch(label)
            # Verify each of the two Pods, not just the Service's chosen endpoint.
            pods = json.loads(
                kubectl(
                    "-n",
                    "acr-system",
                    "get",
                    "pods",
                    "-l",
                    "app=acr-gateway",
                    "-o",
                    "json",
                    capture_output=True,
                ).stdout
            )["items"]
            for pod in pods:
                if pod["metadata"].get("deletionTimestamp"):
                    continue
                result = kubectl(
                    "-n",
                    "acr-system",
                    "exec",
                    pod["metadata"]["name"],
                    "-c",
                    "gateway",
                    "--",
                    "python",
                    "-c",
                    direct_opa_probe(),
                    capture_output=True,
                )
                OUT.joinpath(label + "-" + pod["metadata"]["name"] + "-opa.json").write_text(
                    result.stdout
                )
                kubectl(
                    "-n",
                    "acr-system",
                    "exec",
                    pod["metadata"]["name"],
                    "-c",
                    "gateway",
                    "--",
                    "curl",
                    "-fsS",
                    "http://127.0.0.1:8000/acr/ready",
                )
    finally:
        proc.terminate()
        proc.wait(timeout=10)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime", choices=["docker", "kind"])
    args = parser.parse_args()
    (docker_test if args.runtime == "docker" else kind_test)()
