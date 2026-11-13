export class ACRHttpError extends Error {
    statusCode;
    body;
    constructor(statusCode, message, body) {
        super(message);
        this.name = "ACRHttpError";
        this.statusCode = statusCode;
        this.body = body;
    }
}
export class ACRDecisionError extends Error {
    response;
    constructor(response) {
        super(response.reason ?? `ACR decision '${response.decision}' blocked execution`);
        this.name = "ACRDecisionError";
        this.response = response;
    }
}
export class ACRDeniedError extends ACRDecisionError {
    constructor(response) {
        super(response);
        this.name = "ACRDeniedError";
    }
}
export class ACREscalatedError extends ACRDecisionError {
    constructor(response) {
        super(response);
        this.name = "ACREscalatedError";
    }
}
function normalizeBaseUrl(baseUrl) {
    return baseUrl.replace(/\/+$/, "");
}
function ensureOperatorApiKey(apiKey) {
    if (!apiKey) {
        throw new Error("operatorApiKey is required for operator endpoints");
    }
    return apiKey;
}
async function parseResponseBody(response) {
    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
        return response.json();
    }
    return response.text();
}
function assertRunnableDecision(response) {
    if (response.decision === "deny") {
        throw new ACRDeniedError(response);
    }
    if (response.decision === "escalate") {
        throw new ACREscalatedError(response);
    }
    return response;
}
export { assertRunnableDecision };
export class ACRClient {
    baseUrl;
    operatorApiKey;
    fetchImpl;
    constructor(options) {
        this.baseUrl = normalizeBaseUrl(options.baseUrl);
        this.operatorApiKey = options.operatorApiKey;
        this.fetchImpl = options.fetchImpl ?? fetch;
    }
    operatorHeaders() {
        return {
            "Content-Type": "application/json",
            "X-Operator-API-Key": ensureOperatorApiKey(this.operatorApiKey)
        };
    }
    agentHeaders(accessToken) {
        return {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${accessToken}`
        };
    }
    async requestJson(path, init, expectedStatuses = [200, 201]) {
        const response = await this.fetchImpl(`${this.baseUrl}${path}`, init);
        const body = await parseResponseBody(response);
        if (!expectedStatuses.includes(response.status)) {
            throw new ACRHttpError(response.status, `ACR API request failed with status ${response.status}`, body);
        }
        return body;
    }
    async registerAgent(request) {
        return this.requestJson("/acr/agents", {
            method: "POST",
            headers: this.operatorHeaders(),
            body: JSON.stringify(request)
        });
    }
    async ensureAgentRegistered(request) {
        const response = await this.fetchImpl(`${this.baseUrl}/acr/agents`, {
            method: "POST",
            headers: this.operatorHeaders(),
            body: JSON.stringify(request)
        });
        const body = await parseResponseBody(response);
        if (response.status === 409) {
            return this.getAgent(request.agent_id);
        }
        if (response.status !== 201) {
            throw new ACRHttpError(response.status, `ACR API request failed with status ${response.status}`, body);
        }
        return body;
    }
    async getAgent(agentId) {
        return this.requestJson(`/acr/agents/${agentId}`, {
            method: "GET",
            headers: this.operatorHeaders()
        });
    }
    async issueAgentToken(agentId) {
        return this.requestJson(`/acr/agents/${agentId}/token`, {
            method: "POST",
            headers: this.operatorHeaders()
        });
    }
    createAgentSession(agentId, accessToken) {
        return new ACRAgentSession(this, agentId, accessToken);
    }
    async issueAgentSession(agentId) {
        const token = await this.issueAgentToken(agentId);
        return this.createAgentSession(token.agent_id, token.access_token);
    }
    async evaluate(request, accessToken) {
        const response = await this.fetchImpl(`${this.baseUrl}/acr/evaluate`, {
            method: "POST",
            headers: this.agentHeaders(accessToken),
            body: JSON.stringify(request)
        });
        const body = await parseResponseBody(response);
        const expectedStatuses = new Set([200, 202, 403, 500, 503]);
        if (!expectedStatuses.has(response.status)) {
            throw new ACRHttpError(response.status, `Unexpected evaluate response status ${response.status}`, body);
        }
        return body;
    }
    async evaluateAction(agentId, accessToken, action, context = {}, intent) {
        return this.evaluate({
            agent_id: agentId,
            action: {
                tool_name: action.tool_name,
                parameters: action.parameters ?? {},
                description: action.description
            },
            context,
            intent
        }, accessToken);
    }
    async getHealth() {
        return this.requestJson("/acr/health", {
            method: "GET"
        }, [200]);
    }
    async getReady() {
        return this.requestJson("/acr/ready", {
            method: "GET"
        }, [200, 503]);
    }
}
export class ACRAgentSession {
    client;
    agentId;
    accessToken;
    constructor(client, agentId, accessToken) {
        this.client = client;
        this.agentId = agentId;
        this.accessToken = accessToken;
    }
    async refreshToken() {
        const token = await this.client.issueAgentToken(this.agentId);
        this.accessToken = token.access_token;
        return token;
    }
    async evaluate(request) {
        if (request.agent_id !== this.agentId) {
            throw new Error("EvaluateRequest.agent_id does not match the bound session agentId");
        }
        return this.client.evaluate(request, this.accessToken);
    }
    async evaluateAction(action, context = {}, intent) {
        return this.client.evaluateAction(this.agentId, this.accessToken, action, context, intent);
    }
}
