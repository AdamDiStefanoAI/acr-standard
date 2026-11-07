"""Verify rendered production deployment structure without deploying it."""

import sys
from pathlib import Path

import yaml

text = Path(sys.argv[1]).read_text()
docs = list(yaml.safe_load_all(text))
gateway = next(
    d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == "acr-gateway"
)
pod = gateway["spec"]["template"]["spec"]
images = [c["image"] for c in pod["initContainers"] + pod["containers"] if c["name"] != "opa"]
assert len(images) == 3 and len(set(images)) == 1, images
assert images[0] == "ghcr.io/adamdistefanoai/acr-standard/acr-gateway:1.3.0", images
assert all("--no-auth" not in c.get("command", []) for c in pod["initContainers"])
opa = next(c for c in pod["containers"] if c["name"] == "opa")
assert opa["image"] == "openpolicyagent/opa:0.70.0"
assert "--addr=127.0.0.1:8181" in opa["args"]
assert opa["env"][0]["valueFrom"]["secretKeyRef"]["key"] == "SERVICE_OPERATOR_API_KEY"
config = next(
    d for d in docs if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "acr-gateway-config"
)
assert config["data"]["REQUIRE_BUNDLE_AUTH"] == "true"
assert config["data"]["OPA_URL"] == "http://127.0.0.1:8181"
assert "acr-opa" not in text and "discovery.resource" not in text
print("PASS: production render has one paired image, authenticated local polling, no shared OPA")
