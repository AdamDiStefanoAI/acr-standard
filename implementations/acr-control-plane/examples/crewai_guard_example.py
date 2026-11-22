"""
Guard CrewAI tools with ACR runtime enforcement.

Requires: pip install acr-control-plane crewai

The pattern: build your CrewAI tools the usual way, then pass each one
through guard_crewai_tool. ACR authorizes every call before it executes;
denied actions raise ACRDeniedError and the tool body never runs.
"""

from crewai.tools import tool as crewai_tool

from acr.pillar1_identity.models import AgentRegisterRequest
from acr.sdk import ACRClient
from acr.sdk.crewai import guard_crewai_tool, guard_crewai_tools

# --- ACR setup (once per process) -------------------------------------------
client = ACRClient(base_url="http://localhost:8000", operator_api_key="<redacted>")
client.ensure_agent_registered(
    AgentRegisterRequest(
        agent_id="ops-agent",
        owner="ops@example.com",
        purpose="Run governed operations tasks",
        allowed_tools=["restart_service"],
        forbidden_tools=["delete_database"],
    )
)
session = client.issue_agent_session("ops-agent")


# --- CrewAI tools (unchanged from an unguarded crew) --------------------------
@crewai_tool("restart_service")
def restart_service(service_name: str) -> str:
    """Restart a named service."""
    # ... your implementation ...
    return f"restarted {service_name}"


@crewai_tool("delete_database")
def delete_database(database_name: str) -> str:
    """Delete a database. Forbidden by policy; every call is denied."""
    return f"deleted {database_name}"


# --- Guard them (one line per tool, or guard the whole list at once) ---------
guarded_tools = guard_crewai_tools(
    [restart_service, delete_database],
    session=session,
)

# Equivalent for a single tool:
# restart_service = guard_crewai_tool(restart_service, session=session)

# Wire guarded_tools into your CrewAI agents as usual.
