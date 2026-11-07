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


def evaluate(parameters):
    status, token = request("POST", "/acr/agents/upgrade-ci/token", {}, OPERATOR)
    assert status == 200, token
    return request(
        "POST",
        "/acr/evaluate",
        {
            "agent_id": "upgrade-ci",
            "action": {"tool_name": "query_customer_db", "parameters": parameters},
        },
        {"Authorization": "Bearer " + token["access_token"]},
    )


def assert_policy(label):
    wait_ready()
    for parameters, expected in [
        ({"customer_id": "C-12345"}, "allow"),
        ({"migration_sentinel": True}, "deny"),
        ({"studio_sentinel": True}, "deny"),
    ]:
        status, result = evaluate(parameters)
        assert result.get("decision") == expected, (label, status, result)
    status, archive = request("GET", "/acr/policy-bundles/active.tar.gz", headers=OPERATOR)
    assert status == 200
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        sources = "\n".join(
            bundle.extractfile(n).read().decode() for n in bundle.getnames() if n.endswith(".rego")
        )
    assert "migration_sentinel" in sources and "studio_sentinel" in sources
    OUT.joinpath(label + ".txt").write_text(
        "PASS: readiness, core match, allow, local deny, active Studio deny\n"
    )


def seed():
    wait_ready()
    status, body = request("POST", "/acr/agents", MANIFEST, OPERATOR)
    assert status == 201, (status, body)
    status, draft = request(
        "POST",
        "/acr/policy-drafts",
        {
            "name": "Persistent Studio sentinel",
            "agent_id": "upgrade-ci",
            "template": "customer_support",
            "manifest": MANIFEST,
            "rego_policy": 'package acr\nimport future.keywords.if\nimport future.keywords.contains\ndeny contains "Studio sentinel" if { input.action.parameters.studio_sentinel == true }',
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
    # OPA polls asynchronously; do not mistake initial core readiness for active policy arrival.
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if evaluate({"studio_sentinel": True})[1].get("decision") == "deny":
            return
        time.sleep(2)
    raise AssertionError("Studio policy did not propagate")


def compose(*args):
    assert os.environ["COMPOSE_PROJECT_NAME"].startswith("acr-managed-")
    run("docker", "compose", *args)


def docker_test():
    compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180")
    seed()
    assert_policy("docker-before")
    # Deliberately upgrade gateway alone: its pinned core must refuse old loaded OPA.
    os.environ["ACR_GATEWAY_IMAGE"] = "acr-gateway:upgrade-ci-next"
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
    os.environ["ACR_GATEWAY_IMAGE"] = "acr-gateway:upgrade-ci-old"
    compose("run", "--rm", "--no-deps", "acr-policy-export")
    compose("up", "-d", "--no-build", "--no-deps", "--force-recreate", "acr-gateway", "opa")
    assert_policy("docker-rollback")


def kubectl(*args, **kw):
    return run("kubectl", "--context", "kind-acr-managed-ci", *args, **kw)


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
