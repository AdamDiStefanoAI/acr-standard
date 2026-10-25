"""Official Python SDK for the ACR control plane."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx
from pydantic import BaseModel

from acr.gateway.models import ActionRequest, EvaluateRequest, EvaluateResponse, IntentRequest
from acr.pillar1_identity.models import AgentRegisterRequest, AgentResponse, TokenResponse
from acr.sdk.errors import ACRHTTPError

_EVALUATE_STATUS_CODES = {200, 202, 403, 500, 503}


def _jsonable(payload: BaseModel | Mapping[str, Any] | None) -> dict[str, Any]:
    if payload is None:
        return {}
    if isinstance(payload, BaseModel):
        return payload.model_dump(mode="json", exclude_none=True)
    return dict(payload)


def _parse_json_response(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text


def _raise_http_error(response: httpx.Response) -> None:
    body = _parse_json_response(response)
    message = f"ACR API request failed with status {response.status_code}"
    if isinstance(body, dict):
        detail = body.get("detail") or body.get("reason") or body.get("message")
        if detail:
            message = f"{message}: {detail}"
    raise ACRHTTPError(status_code=response.status_code, message=message, body=body)


def _parse_model(response: httpx.Response, model_type):
    if response.is_error:
        _raise_http_error(response)
    return model_type.model_validate(response.json())


def _parse_evaluate_response(
    response: httpx.Response, *, expected_tool_name: str
) -> EvaluateResponse:
    payload = _parse_json_response(response)
    if response.status_code not in _EVALUATE_STATUS_CODES:
        raise ACRHTTPError(
            status_code=response.status_code,
            message=f"Unexpected evaluate response status {response.status_code}",
            body=payload,
        )
    if not isinstance(payload, dict):
        raise ACRHTTPError(
            status_code=response.status_code,
            message="Evaluate response body was not JSON",
            body=payload,
        )
    result = EvaluateResponse.model_validate(payload)
    # Only a successful evaluation may authorize execution. Preserve structured
    # deny/escalate results on supported failure statuses, but never let a
    # contradictory response body turn an error or pending status into allow.
    if response.status_code != 200 and result.is_allowed:
        raise ACRHTTPError(
            status_code=response.status_code,
            message="Non-success evaluate response cannot authorize execution",
            body=payload,
        )
    # Validate transformation completeness and action identity for raw SDK
    # callers too, not only callers using the optional local guard wrappers.
    modified = result.modified_action
    if result.decision == "modify" and modified is None:
        raise ACRHTTPError(
            status_code=response.status_code,
            message="MODIFY response requires an explicit modified action",
            body=payload,
        )
    if modified is not None and (
        modified.tool_name != expected_tool_name or "parameters" not in modified.model_fields_set
    ):
        raise ACRHTTPError(
            status_code=response.status_code,
            message="Modified action must match the requested tool and include explicit parameters",
            body=payload,
        )
    return result


class ACRClient:
    """Synchronous ACR client for agent onboarding and runtime decisions."""

    def __init__(
        self,
        *,
        base_url: str,
        operator_api_key: str | None = None,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.operator_api_key = operator_api_key
        self._owns_client = client is None
        self._client = client or httpx.Client(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
        )

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> ACRClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _operator_headers(self) -> dict[str, str]:
        if not self.operator_api_key:
            raise ValueError("operator_api_key is required for operator endpoints")
        return {"X-Operator-API-Key": self.operator_api_key}

    @staticmethod
    def _agent_headers(access_token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {access_token}"}

    def register_agent(self, request: AgentRegisterRequest) -> AgentResponse:
        response = self._client.post(
            "/acr/agents",
            headers=self._operator_headers(),
            json=_jsonable(request),
        )
        return _parse_model(response, AgentResponse)

    def ensure_agent_registered(self, request: AgentRegisterRequest) -> AgentResponse:
        response = self._client.post(
            "/acr/agents",
            headers=self._operator_headers(),
            json=_jsonable(request),
        )
        if response.status_code == 409:
            return self.get_agent(request.agent_id)
        return _parse_model(response, AgentResponse)

    def get_agent(self, agent_id: str) -> AgentResponse:
        response = self._client.get(f"/acr/agents/{agent_id}", headers=self._operator_headers())
        return _parse_model(response, AgentResponse)

    def issue_agent_token(self, agent_id: str) -> TokenResponse:
        response = self._client.post(
            f"/acr/agents/{agent_id}/token",
            headers=self._operator_headers(),
        )
        return _parse_model(response, TokenResponse)

    def get_health(self) -> dict[str, Any]:
        response = self._client.get("/acr/health")
        if response.is_error:
            _raise_http_error(response)
        payload = _parse_json_response(response)
        if not isinstance(payload, dict):
            raise ACRHTTPError(
                status_code=response.status_code,
                message="Health response body was not JSON",
                body=payload,
            )
        return payload

    def get_ready(self) -> dict[str, Any]:
        response = self._client.get("/acr/ready")
        if response.status_code not in {200, 503}:
            _raise_http_error(response)
        payload = _parse_json_response(response)
        if not isinstance(payload, dict):
            raise ACRHTTPError(
                status_code=response.status_code,
                message="Ready response body was not JSON",
                body=payload,
            )
        return payload

    def create_agent_session(self, agent_id: str, access_token: str) -> ACRAgentSession:
        return ACRAgentSession(client=self, agent_id=agent_id, access_token=access_token)

    def issue_agent_session(self, agent_id: str) -> ACRAgentSession:
        token = self.issue_agent_token(agent_id)
        return self.create_agent_session(token.agent_id, token.access_token)

    def evaluate(self, request: EvaluateRequest, *, access_token: str) -> EvaluateResponse:
        response = self._client.post(
            "/acr/evaluate",
            headers=self._agent_headers(access_token),
            json=_jsonable(request),
        )
        return _parse_evaluate_response(response, expected_tool_name=request.action.tool_name)

    def evaluate_action(
        self,
        *,
        agent_id: str,
        access_token: str,
        tool_name: str,
        parameters: Mapping[str, Any] | None = None,
        description: str | None = None,
        context: Mapping[str, Any] | None = None,
        intent: IntentRequest | Mapping[str, Any] | None = None,
    ) -> EvaluateResponse:
        request = EvaluateRequest(
            agent_id=agent_id,
            action=ActionRequest(
                tool_name=tool_name,
                parameters=dict(parameters or {}),
                description=description,
            ),
            context=dict(context or {}),
            intent=IntentRequest.model_validate(intent) if intent is not None else None,
        )
        return self.evaluate(request, access_token=access_token)


class AsyncACRClient:
    """Async ACR client for agent onboarding and runtime decisions."""

    def __init__(
        self,
        *,
        base_url: str,
        operator_api_key: str | None = None,
        timeout: float = 10.0,
        client: httpx.AsyncClient | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.operator_api_key = operator_api_key
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=self.base_url,
            timeout=timeout,
            transport=transport,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AsyncACRClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    def _operator_headers(self) -> dict[str, str]:
        if not self.operator_api_key:
            raise ValueError("operator_api_key is required for operator endpoints")
        return {"X-Operator-API-Key": self.operator_api_key}

    @staticmethod
    def _agent_headers(access_token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {access_token}"}

    async def register_agent(self, request: AgentRegisterRequest) -> AgentResponse:
        response = await self._client.post(
            "/acr/agents",
            headers=self._operator_headers(),
            json=_jsonable(request),
        )
        return _parse_model(response, AgentResponse)

    async def ensure_agent_registered(self, request: AgentRegisterRequest) -> AgentResponse:
        response = await self._client.post(
            "/acr/agents",
            headers=self._operator_headers(),
            json=_jsonable(request),
        )
        if response.status_code == 409:
            return await self.get_agent(request.agent_id)
        return _parse_model(response, AgentResponse)

    async def get_agent(self, agent_id: str) -> AgentResponse:
        response = await self._client.get(
            f"/acr/agents/{agent_id}", headers=self._operator_headers()
        )
        return _parse_model(response, AgentResponse)

    async def issue_agent_token(self, agent_id: str) -> TokenResponse:
        response = await self._client.post(
            f"/acr/agents/{agent_id}/token",
            headers=self._operator_headers(),
        )
        return _parse_model(response, TokenResponse)

    async def get_health(self) -> dict[str, Any]:
        response = await self._client.get("/acr/health")
        if response.is_error:
            _raise_http_error(response)
        payload = _parse_json_response(response)
        if not isinstance(payload, dict):
            raise ACRHTTPError(
                status_code=response.status_code,
                message="Health response body was not JSON",
                body=payload,
            )
        return payload

    async def get_ready(self) -> dict[str, Any]:
        response = await self._client.get("/acr/ready")
        if response.status_code not in {200, 503}:
            _raise_http_error(response)
        payload = _parse_json_response(response)
        if not isinstance(payload, dict):
            raise ACRHTTPError(
                status_code=response.status_code,
                message="Ready response body was not JSON",
                body=payload,
            )
        return payload

    def create_agent_session(self, agent_id: str, access_token: str) -> AsyncACRAgentSession:
        return AsyncACRAgentSession(client=self, agent_id=agent_id, access_token=access_token)

    async def issue_agent_session(self, agent_id: str) -> AsyncACRAgentSession:
        token = await self.issue_agent_token(agent_id)
        return self.create_agent_session(token.agent_id, token.access_token)

    async def evaluate(self, request: EvaluateRequest, *, access_token: str) -> EvaluateResponse:
        response = await self._client.post(
            "/acr/evaluate",
            headers=self._agent_headers(access_token),
            json=_jsonable(request),
        )
        return _parse_evaluate_response(response, expected_tool_name=request.action.tool_name)

    async def evaluate_action(
        self,
        *,
        agent_id: str,
        access_token: str,
        tool_name: str,
        parameters: Mapping[str, Any] | None = None,
        description: str | None = None,
        context: Mapping[str, Any] | None = None,
        intent: IntentRequest | Mapping[str, Any] | None = None,
    ) -> EvaluateResponse:
        request = EvaluateRequest(
            agent_id=agent_id,
            action=ActionRequest(
                tool_name=tool_name,
                parameters=dict(parameters or {}),
                description=description,
            ),
            context=dict(context or {}),
            intent=IntentRequest.model_validate(intent) if intent is not None else None,
        )
        return await self.evaluate(request, access_token=access_token)


class ACRAgentSession:
    """Bound sync session for a specific agent and token."""

    def __init__(self, *, client: ACRClient, agent_id: str, access_token: str) -> None:
        self.client = client
        self.agent_id = agent_id
        self.access_token = access_token

    def refresh_token(self) -> TokenResponse:
        token = self.client.issue_agent_token(self.agent_id)
        self.access_token = token.access_token
        return token

    def evaluate(self, request: EvaluateRequest) -> EvaluateResponse:
        if request.agent_id != self.agent_id:
            raise ValueError("EvaluateRequest.agent_id does not match the bound session agent_id")
        return self.client.evaluate(request, access_token=self.access_token)

    def evaluate_action(
        self,
        *,
        tool_name: str,
        parameters: Mapping[str, Any] | None = None,
        description: str | None = None,
        context: Mapping[str, Any] | None = None,
        intent: IntentRequest | Mapping[str, Any] | None = None,
    ) -> EvaluateResponse:
        return self.client.evaluate_action(
            agent_id=self.agent_id,
            access_token=self.access_token,
            tool_name=tool_name,
            parameters=parameters,
            description=description,
            context=context,
            intent=intent,
        )


class AsyncACRAgentSession:
    """Bound async session for a specific agent and token."""

    def __init__(self, *, client: AsyncACRClient, agent_id: str, access_token: str) -> None:
        self.client = client
        self.agent_id = agent_id
        self.access_token = access_token

    async def refresh_token(self) -> TokenResponse:
        token = await self.client.issue_agent_token(self.agent_id)
        self.access_token = token.access_token
        return token

    async def evaluate(self, request: EvaluateRequest) -> EvaluateResponse:
        if request.agent_id != self.agent_id:
            raise ValueError("EvaluateRequest.agent_id does not match the bound session agent_id")
        return await self.client.evaluate(request, access_token=self.access_token)

    async def evaluate_action(
        self,
        *,
        tool_name: str,
        parameters: Mapping[str, Any] | None = None,
        description: str | None = None,
        context: Mapping[str, Any] | None = None,
        intent: IntentRequest | Mapping[str, Any] | None = None,
    ) -> EvaluateResponse:
        return await self.client.evaluate_action(
            agent_id=self.agent_id,
            access_token=self.access_token,
            tool_name=tool_name,
            parameters=parameters,
            description=description,
            context=context,
            intent=intent,
        )
