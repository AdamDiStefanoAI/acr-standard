"""Real-signature regression coverage for the python-jose to PyJWT migration."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from unittest.mock import AsyncMock

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from acr.common.errors import (
    InvalidExecutionAuthorizationError,
    InvalidTokenError,
    TokenExpiredError,
    UnauthorizedOperatorError,
)
from acr.common.oidc import create_signed_payload, decode_signed_payload, validate_oidc_token
from acr.config import settings
from acr.gateway.executor_auth import (
    build_brokered_execution_credential,
    build_execution_token,
    execution_payload_sha256,
    verify_brokered_execution_credential,
    verify_execution_token,
)
from acr.pillar1_identity.validator import decode_token, issue_token

_SECRET = "a" * 64
_PAYLOAD = {"tool_name": "query_customer_db", "parameters": {"customer_id": "C-001"}}


@pytest.fixture(scope="module")
def signing_keys():
    return {
        "RS256": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "ES256": ec.generate_private_key(ec.SECP256R1()),
    }


@pytest.fixture(autouse=True)
def configure_secrets(monkeypatch):
    monkeypatch.setattr(settings, "jwt_secret_key", _SECRET)
    monkeypatch.setattr(settings, "jwt_algorithm", "HS256")
    monkeypatch.setattr(settings, "executor_hmac_secret", _SECRET)
    monkeypatch.setattr(settings, "executor_credential_secret", _SECRET)
    monkeypatch.setattr(settings, "operator_session_secret", _SECRET)


def _claims(**overrides):
    now = int(time.time())
    return {"sub": "agent-1", "iat": now, "exp": now + 300, **overrides}


def _forged_hmac_token(claims, secret):
    """Construct an attack token without relying on an encoder's key guard."""

    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")

    message = encode({"alg": "HS256", "typ": "JWT", "kid": "key-1"}) + b"." + encode(claims)
    signature = base64.urlsafe_b64encode(hmac.digest(secret, message, hashlib.sha256)).rstrip(b"=")
    return (message + b"." + signature).decode()


@pytest.mark.parametrize("algorithm", ["HS256", "RS256", "ES256"])
def test_agent_issue_and_decode_preserves_supported_algorithms(
    monkeypatch, signing_keys, algorithm
):
    monkeypatch.setattr(settings, "jwt_algorithm", algorithm)
    if algorithm != "HS256":
        key = signing_keys[algorithm]
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        monkeypatch.setattr(settings, "jwt_secret_key", private_pem)
    token, expires = issue_token("agent-1")
    assert expires > 0
    assert decode_token(token) == "agent-1"
    if algorithm != "HS256":
        public_pem = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        monkeypatch.setattr(settings, "jwt_secret_key", public_pem)
        assert decode_token(token) == "agent-1"


def test_agent_accepts_existing_python_jose_token():
    # Generated with python-jose 3.5.0, key "a" * 64, and a 2100 expiration.
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJsZWdhY3ktYWdlbnQiLCJleHAiOjQxMDI0NDQ4MDAsImlhdCI6MTcwNDA2NzIwMCwi"
        "aXNzIjoiYWNyLWNvbnRyb2wtcGxhbmUifQ.tmOGDnCpJu-TwgOBHX6AIbSoVPIIJqtl2KZXkyg572k"
    )
    assert decode_token(token) == "legacy-agent"


@pytest.mark.parametrize("algorithm", ["none", "HS512"])
def test_agent_rejects_unconfigured_algorithm(algorithm):
    token = jwt.encode(_claims(), "" if algorithm == "none" else _SECRET, algorithm=algorithm)
    with pytest.raises(InvalidTokenError):
        decode_token(token)


def test_agent_rejects_wrong_signature():
    token = jwt.encode(_claims(), "b" * 64, algorithm="HS256")
    with pytest.raises(InvalidTokenError):
        decode_token(token)


def test_agent_preserves_expired_error():
    token = jwt.encode(_claims(exp=int(time.time()) - 30), _SECRET, algorithm="HS256")
    with pytest.raises(TokenExpiredError, match="expired"):
        decode_token(token)


@pytest.mark.parametrize("claim", ["iat", "nbf"])
def test_agent_rejects_future_claims(claim):
    token = jwt.encode(_claims(**{claim: int(time.time()) + 60}), _SECRET, algorithm="HS256")
    with pytest.raises(InvalidTokenError):
        decode_token(token)


def test_agent_rejects_der_public_key_hmac_confusion(monkeypatch, signing_keys):
    public_key = signing_keys["RS256"].public_key()
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    forged = _forged_hmac_token(_claims(), der)
    monkeypatch.setattr(settings, "jwt_algorithm", "RS256")
    monkeypatch.setattr(
        settings,
        "jwt_secret_key",
        public_key.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(),
    )
    with pytest.raises(InvalidTokenError):
        decode_token(forged)


@pytest.fixture(params=["RS256", "ES256"])
def oidc_signer(request, monkeypatch, signing_keys):
    algorithm = request.param
    key = signing_keys[algorithm]
    jwk = jwt.get_algorithm_by_name(algorithm).to_jwk(key.public_key(), as_dict=True)
    jwk.update({"kid": "key-1", "alg": algorithm, "use": "sig"})
    monkeypatch.setattr(settings, "oidc_enabled", True)
    monkeypatch.setattr(settings, "oidc_client_id", "client-1")
    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.example.com")
    monkeypatch.setattr(settings, "oidc_subject_claim", "email")
    monkeypatch.setattr("acr.common.oidc._fetch_jwks", AsyncMock(return_value={"keys": [jwk]}))

    def sign(**overrides):
        claims = _claims(
            iss="https://idp.example.com",
            aud="client-1",
            email="alice@example.com",
            nonce="nonce-1",
        )
        claims.update(overrides)
        return jwt.encode(claims, key, algorithm=algorithm, headers={"kid": "key-1"})

    return sign


async def test_oidc_accepts_real_asymmetric_signature(oidc_signer):
    principal = await validate_oidc_token(oidc_signer(), nonce="nonce-1")
    assert principal.subject == "alice@example.com"


@pytest.mark.parametrize(
    "overrides",
    [
        {"aud": "other-client"},
        {"iss": "https://other-idp.example.com"},
        {"exp": 1},
        {"nonce": "wrong-nonce"},
        {"at_hash": "unverifiable"},
    ],
)
async def test_oidc_rejects_invalid_claims(oidc_signer, overrides):
    with pytest.raises(UnauthorizedOperatorError):
        await validate_oidc_token(oidc_signer(**overrides), nonce="nonce-1")


async def test_oidc_rejects_forged_hmac_signature(oidc_signer, signing_keys):
    public_key = (
        signing_keys["RS256"]
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    token = _forged_hmac_token(_claims(iss="https://idp.example.com", aud="client-1"), public_key)
    with pytest.raises(UnauthorizedOperatorError):
        await validate_oidc_token(token)


async def test_oidc_rejects_malformed_token(oidc_signer):
    with pytest.raises(UnauthorizedOperatorError, match="invalid"):
        await validate_oidc_token("not-a-jwt")


async def test_oidc_rejects_malformed_jwk(monkeypatch, oidc_signer):
    monkeypatch.setattr(
        "acr.common.oidc._fetch_jwks",
        AsyncMock(return_value={"keys": [{"kid": "key-1", "kty": "RSA", "n": "bad"}]}),
    )
    with pytest.raises(UnauthorizedOperatorError, match="invalid"):
        await validate_oidc_token(oidc_signer())


def test_execution_and_brokered_credentials_round_trip():
    token = build_execution_token(
        agent_id="agent-1", tool_name="query_customer_db", correlation_id="corr-1", payload=_PAYLOAD
    )
    assert verify_execution_token(token, payload=_PAYLOAD).agent_id == "agent-1"
    credential = build_brokered_execution_credential(
        agent_id="agent-1",
        tool_name="query_customer_db",
        correlation_id="corr-1",
        audience="tool:query_customer_db",
        scopes=["execute"],
        payload=_PAYLOAD,
    )
    assert verify_brokered_execution_credential(
        credential, audience="tool:query_customer_db"
    ).scopes == ("execute",)
    assert verify_brokered_execution_credential(
        credential, audience="tool:query_customer_db", payload=_PAYLOAD
    ).payload_sha256 == execution_payload_sha256(_PAYLOAD)
    with pytest.raises(InvalidExecutionAuthorizationError):
        verify_brokered_execution_credential(
            credential, audience="tool:query_customer_db", payload={"tampered": True}
        )
    with pytest.raises(InvalidExecutionAuthorizationError):
        verify_brokered_execution_credential(credential, audience="tool:other")
    with pytest.raises(InvalidExecutionAuthorizationError):
        verify_execution_token(token, payload={"tampered": True})


@pytest.mark.parametrize("brokered", [False, True])
@pytest.mark.parametrize(
    "failure", ["expired", "issuer", "signature", "algorithm", "not-yet-valid", "at-hash"]
)
def test_executor_rejects_invalid_tokens(brokered, failure):
    claims = _claims(
        iss="acr-control-plane",
        agent_id="agent-1",
        tool_name="query_customer_db",
        correlation_id="corr-1",
        payload_sha256=execution_payload_sha256(_PAYLOAD),
        scopes=["execute"],
    )
    if brokered:
        claims["aud"] = "tool:query_customer_db"
    if failure == "expired":
        claims["exp"] = 1
    elif failure == "issuer":
        claims["iss"] = "attacker"
    elif failure == "not-yet-valid":
        claims["nbf"] = int(time.time()) + 60
    elif failure == "at-hash":
        claims["at_hash"] = "unverifiable"
    secret = "b" * 64 if failure == "signature" else _SECRET
    algorithm = "HS512" if failure == "algorithm" else "HS256"
    token = jwt.encode(claims, secret, algorithm=algorithm)
    with pytest.raises(InvalidExecutionAuthorizationError):
        if brokered:
            verify_brokered_execution_credential(token, audience="tool:query_customer_db")
        else:
            verify_execution_token(token, payload=_PAYLOAD)


def test_operator_session_round_trip():
    token = create_signed_payload({"subject": "operator-1"}, ttl_seconds=300)
    assert decode_signed_payload(token)["subject"] == "operator-1"


@pytest.mark.parametrize("failure", ["expired", "signature", "algorithm"])
def test_operator_session_rejects_invalid_tokens(failure):
    claims = _claims(exp=1) if failure == "expired" else _claims()
    token = jwt.encode(
        claims,
        "b" * 64 if failure == "signature" else _SECRET,
        algorithm="HS512" if failure == "algorithm" else "HS256",
    )
    with pytest.raises(jwt.PyJWTError):
        decode_signed_payload(token)


@pytest.mark.parametrize(
    "claims",
    [
        {"at_hash": "unverifiable"},
        {"aud": ""},
        {"aud": []},
        {"aud": None},
    ],
)
@pytest.mark.parametrize("consumer", ["agent", "session", "executor"])
def test_local_tokens_reject_previously_invalid_claims(claims, consumer):
    payload = _claims(
        iss="acr-control-plane",
        agent_id="agent-1",
        tool_name="query_customer_db",
        correlation_id="corr-1",
        payload_sha256=execution_payload_sha256(_PAYLOAD),
        **claims,
    )
    token = jwt.encode(payload, _SECRET, algorithm="HS256")
    if consumer == "agent":
        with pytest.raises(InvalidTokenError):
            decode_token(token)
    elif consumer == "session":
        with pytest.raises(jwt.PyJWTError):
            decode_signed_payload(token)
    else:
        with pytest.raises(InvalidExecutionAuthorizationError):
            verify_execution_token(token, payload=_PAYLOAD)


async def test_oidc_binds_allowlisted_algorithm_to_selected_jwk(oidc_signer, signing_keys):
    valid = oidc_signer()
    header = jwt.get_unverified_header(valid)
    signing_algorithm = header["alg"]
    header["alg"] = "ES256" if signing_algorithm == "RS256" else "RS256"
    encoded_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
    signing_input = encoded_header + b"." + valid.split(".")[1].encode()
    # Both header algorithms are allowlisted, but the signature uses the JWK's
    # other algorithm. Verification must bind the header to that selected JWK.
    signature = jwt.get_algorithm_by_name(signing_algorithm).sign(
        signing_input, signing_keys[signing_algorithm]
    )
    token = (signing_input + b"." + base64.urlsafe_b64encode(signature).rstrip(b"=")).decode()
    with pytest.raises(UnauthorizedOperatorError) as caught:
        await validate_oidc_token(token)
    assert isinstance(caught.value.__cause__, jwt.InvalidAlgorithmError)
