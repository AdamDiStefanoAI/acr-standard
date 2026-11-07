"""Source configuration regression; does not claim a Docker execution pass."""

from pathlib import Path

import yaml


def test_compose_forwards_both_execution_secrets_to_gateway():
    root = Path(__file__).resolve().parents[1]
    document = yaml.safe_load((root / "docker-compose.yml").read_text())
    environment = document["services"]["acr-gateway"]["environment"]
    assert environment["EXECUTOR_HMAC_SECRET"] == "${EXECUTOR_HMAC_SECRET:-}"
    assert environment["EXECUTOR_CREDENTIAL_SECRET"] == "${EXECUTOR_CREDENTIAL_SECRET:-}"


def test_compose_forwards_same_killswitch_secret_to_gateway_and_service():
    root = Path(__file__).resolve().parents[1]
    document = yaml.safe_load((root / "docker-compose.yml").read_text())
    services = document["services"]
    assert (
        services["acr-gateway"]["environment"]["KILLSWITCH_SECRET"]
        == services["acr-killswitch"]["environment"]["KILLSWITCH_SECRET"]
    )


def test_opa_healthcheck_uses_available_binary_and_requires_http_success():
    root = Path(__file__).resolve().parents[1]
    document = yaml.safe_load((root / "docker-compose.yml").read_text())
    probe = document["services"]["opa"]["healthcheck"]["test"]
    assert probe[:4] == ["CMD", "/opa", "eval", "--fail"]
    assert '"url": "http://127.0.0.1:8181/health?bundles"' in probe[4]
    assert '"timeout": "2s"' in probe[4]
    assert probe[4].endswith(".status_code == 200")


def test_managed_compose_has_no_bundle_readiness_cycle_or_legacy_mount():
    root = Path(__file__).resolve().parents[1]
    services = yaml.safe_load((root / "docker-compose.yml").read_text())["services"]
    assert services["acr-gateway"]["depends_on"]["opa"]["condition"] == "service_started"
    assert (
        services["opa"]["depends_on"]["acr-policy-export"]["condition"]
        == "service_completed_successfully"
    )
    assert "./policies:/policies:ro" not in services["opa"]["volumes"]
    assert services["acr-gateway"]["image"] == services["acr-policy-export"]["image"]
    assert "ACR_BUNDLE_API_KEY" in services["opa"]["environment"]
    assert "--no-auth" not in services["acr-policy-export"]["command"]


def test_kubernetes_pairs_opa_with_release_image_and_preserves_auth():
    root = Path(__file__).resolve().parents[1]
    base = root / "deploy/k8s/base"
    deployment = yaml.safe_load((base / "gateway-deployment.yaml").read_text())
    pod = deployment["spec"]["template"]["spec"]
    gateway, opa = pod["containers"]
    assert (
        gateway["image"] == pod["initContainers"][0]["image"] == pod["initContainers"][1]["image"]
    )
    assert "--addr=127.0.0.1:8181" in opa["args"]
    assert opa["env"][0]["name"] == "ACR_BUNDLE_API_KEY"
    assert "--no-auth" not in pod["initContainers"][0]["command"]
    assert (
        yaml.safe_load((base / "gateway-configmap.yaml").read_text())["data"]["REQUIRE_BUNDLE_AUTH"]
        == "true"
    )
