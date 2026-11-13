export type Decision = "allow" | "deny" | "modify" | "escalate";
export interface ActionRequest {
    tool_name: string;
    parameters?: Record<string, unknown>;
    description?: string;
}
export interface IntentRequest {
    goal?: string;
    justification?: string;
    expected_effects?: string[];
    requested_by_step?: string;
    metadata?: Record<string, unknown>;
}
export interface EvaluateRequest {
    agent_id: string;
    action: ActionRequest;
    context?: Record<string, unknown>;
    intent?: IntentRequest;
}
export interface PolicyDecision {
    policy_id: string;
    decision: Decision;
    reason?: string | null;
    latency_ms?: number | null;
}
export interface EvaluateResponse {
    decision: Decision;
    correlation_id?: string | null;
    reason?: string | null;
    error_code?: string | null;
    approval_request_id?: string | null;
    approval_queue?: string | null;
    sla_minutes?: number | null;
    policy_decisions?: PolicyDecision[];
    drift_score?: number | null;
    latency_ms?: number | null;
    estimated_cost_usd?: number | null;
    authoritative_hourly_spend_usd?: number | null;
    modified_action?: ActionRequest | null;
    execution_result?: Record<string, unknown> | null;
}
export interface AgentBoundaries {
    max_actions_per_minute?: number;
    max_cost_per_hour_usd?: number;
    default_action_cost_usd?: number | null;
    tool_costs_usd?: Record<string, number>;
    allowed_regions?: string[];
    credential_rotation_days?: number;
}
export interface DataAccessEntry {
    resource: string;
    permission?: "READ" | "READ_WRITE" | "WRITE" | "NONE";
}
export interface AgentRegisterRequest {
    agent_id: string;
    owner: string;
    purpose: string;
    risk_tier?: "low" | "medium" | "high";
    allowed_tools?: string[];
    forbidden_tools?: string[];
    data_access?: DataAccessEntry[];
    boundaries?: AgentBoundaries;
    version?: string;
    parent_agent_id?: string | null;
    capabilities?: string[];
    lifecycle_state?: "draft" | "active" | "deprecated" | "retired";
}
export interface AgentResponse extends AgentRegisterRequest {
    is_active: boolean;
    health_status: "unknown" | "healthy" | "degraded" | "unhealthy";
    last_heartbeat_at?: string | null;
    created_at: string;
    updated_at: string;
}
export interface TokenResponse {
    agent_id: string;
    access_token: string;
    token_type: string;
    expires_in_seconds: number;
}
export interface ACRClientOptions {
    baseUrl: string;
    operatorApiKey?: string;
    fetchImpl?: typeof fetch;
}
export declare class ACRHttpError extends Error {
    readonly statusCode: number;
    readonly body: unknown;
    constructor(statusCode: number, message: string, body?: unknown);
}
export declare class ACRDecisionError extends Error {
    readonly response: EvaluateResponse;
    constructor(response: EvaluateResponse);
}
export declare class ACRDeniedError extends ACRDecisionError {
    constructor(response: EvaluateResponse);
}
export declare class ACREscalatedError extends ACRDecisionError {
    constructor(response: EvaluateResponse);
}
declare function assertRunnableDecision(response: EvaluateResponse): EvaluateResponse;
export { assertRunnableDecision };
export declare class ACRClient {
    private readonly baseUrl;
    private readonly operatorApiKey?;
    private readonly fetchImpl;
    constructor(options: ACRClientOptions);
    private operatorHeaders;
    private agentHeaders;
    private requestJson;
    registerAgent(request: AgentRegisterRequest): Promise<AgentResponse>;
    ensureAgentRegistered(request: AgentRegisterRequest): Promise<AgentResponse>;
    getAgent(agentId: string): Promise<AgentResponse>;
    issueAgentToken(agentId: string): Promise<TokenResponse>;
    createAgentSession(agentId: string, accessToken: string): ACRAgentSession;
    issueAgentSession(agentId: string): Promise<ACRAgentSession>;
    evaluate(request: EvaluateRequest, accessToken: string): Promise<EvaluateResponse>;
    evaluateAction(agentId: string, accessToken: string, action: ActionRequest, context?: Record<string, unknown>, intent?: IntentRequest): Promise<EvaluateResponse>;
    getHealth(): Promise<Record<string, unknown>>;
    getReady(): Promise<Record<string, unknown>>;
}
export declare class ACRAgentSession {
    private readonly client;
    readonly agentId: string;
    accessToken: string;
    constructor(client: ACRClient, agentId: string, accessToken: string);
    refreshToken(): Promise<TokenResponse>;
    evaluate(request: EvaluateRequest): Promise<EvaluateResponse>;
    evaluateAction(action: ActionRequest, context?: Record<string, unknown>, intent?: IntentRequest): Promise<EvaluateResponse>;
}
