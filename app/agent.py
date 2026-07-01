# ruff: noqa
import re
import json
from typing import Any
from mcp import StdioServerParameters
from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.adk.workflow import Workflow, Edge, node, START
from google.adk.agents.context import Context
from google.adk.events import RequestInput
from google.adk.tools import AgentTool, McpToolset
from google.adk.tools.mcp_tool import StdioConnectionParams
from pydantic import BaseModel, Field
from app.config import config

# ---------------------------------------------------------------------------
# State Schema
# ---------------------------------------------------------------------------

class ComplianceState(BaseModel):
    original_input: str = ""
    sanitized_input: str = ""
    orchestrator_report: str = ""
    suggests_edits: bool = False
    approved: bool = False
    comments: str = ""
    audit_logs: list[str] = Field(default_factory=list)

# ---------------------------------------------------------------------------
# MCP Toolset Configuration
# ---------------------------------------------------------------------------

mcp_toolset = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command="uv",
            args=["run", "python", "-m", "app.mcp_server"],
        )
    )
)

# ---------------------------------------------------------------------------
# Specialized Sub-Agents & Orchestrator
# ---------------------------------------------------------------------------

gdpr_analyst = Agent(
    name="gdpr_analyst",
    model=Gemini(model=config.model),
    instruction=(
        "You are an expert GDPR compliance analyst. Analyze draft policy texts against GDPR principles "
        "(such as data minimization, lawful basis for processing, consent guidelines, and data subject rights). "
        "Use your tools to fetch regulatory feeds and current policy if needed. "
        "Highlight any potential compliance gaps, risks, or required changes."
    ),
    tools=[mcp_toolset]
)

hipaa_analyst = Agent(
    name="hipaa_analyst",
    model=Gemini(model=config.model),
    instruction=(
        "You are an expert HIPAA compliance analyst. Analyze draft policy texts against HIPAA Security and Privacy "
        "Rules, focusing on Protected Health Information (PHI) safeguards, access controls, and administrative requirements. "
        "Use your tools to fetch regulatory feeds and current policy if needed. "
        "Highlight any gaps, risks, or required policy enhancements."
    ),
    tools=[mcp_toolset]
)

compliance_orchestrator = Agent(
    name="compliance_orchestrator",
    model=Gemini(model=config.model),
    instruction=(
        "You are the Lead Regulatory Compliance Coordinator. Your task is to analyze a policy draft. "
        "Coordinate with specialized analysts: use the gdpr_analyst tool to run GDPR checks, and the "
        "hipaa_analyst tool to run HIPAA checks. Synthesize their findings into a comprehensive compliance report. "
        "If they identify any issues or suggest policy adjustments, you must clearly list the suggested policy edits "
        "under a 'Suggested Edits' heading. If the draft is fully compliant without changes, clearly state "
        "that no policy edits are required."
    ),
    tools=[
        AgentTool(agent=gdpr_analyst),
        AgentTool(agent=hipaa_analyst)
    ]
)


# ---------------------------------------------------------------------------
# Human-In-The-Loop Models
# ---------------------------------------------------------------------------

class ApproveResponse(BaseModel):
    approved: bool
    comments: str

# ---------------------------------------------------------------------------
# Workflow Nodes
# ---------------------------------------------------------------------------

@node
async def security_checkpoint(ctx: Context, node_input: str):
    import logging
    import json
    
    logger = logging.getLogger("compliance_tracker.security")
    
    # Safely initialize session state fields
    if "audit_logs" not in ctx.state:
        ctx.state["audit_logs"] = []
    if "original_input" not in ctx.state:
        ctx.state["original_input"] = ""
    if "sanitized_input" not in ctx.state:
        ctx.state["sanitized_input"] = ""
    if "orchestrator_report" not in ctx.state:
        ctx.state["orchestrator_report"] = ""
    if "suggests_edits" not in ctx.state:
        ctx.state["suggests_edits"] = False
    if "approved" not in ctx.state:
        ctx.state["approved"] = False
    if "comments" not in ctx.state:
        ctx.state["comments"] = ""

    ctx.state["original_input"] = node_input
    
    def log_audit(event_name: str, severity: str, details: dict):
        log_entry = {
            "event": event_name,
            "severity": severity,
            "details": details
        }
        log_str = json.dumps(log_entry)
        logger.info(log_str)
        
        # Explicit copy-assignment to trigger delta-aware state tracking
        logs = list(ctx.state.get("audit_logs", []))
        logs.append(log_str)
        ctx.state["audit_logs"] = logs

    log_audit("checkpoint_initiated", "INFO", {"input_length": len(node_input)})

    # 1. PII Redaction
    redacted = node_input
    # Simple regex for SSN, credit cards, emails
    redacted = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", redacted)
    redacted = re.sub(r"\b(?:\d[ -]?){13,16}\b", "[REDACTED_CARD]", redacted)
    redacted = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[REDACTED_EMAIL]", redacted)
    ctx.state["sanitized_input"] = redacted

    if redacted != node_input:
        detected_types = [t for t, kw in [("SSN", "[REDACTED_SSN]"), ("Credit Card", "[REDACTED_CARD]"), ("Email", "[REDACTED_EMAIL]")] if kw in redacted]
        log_audit("pii_redacted", "WARNING", {"detected_types": detected_types})

    # 2. Prompt Injection Detection
    injection_keywords = ["ignore previous", "system prompt", "override rules", "jailbreak", "do not follow"]
    detected_injections = [kw for kw in injection_keywords if kw in node_input.lower()]

    if detected_injections:
        log_audit("prompt_injection_flagged", "CRITICAL", {"detected_keywords": detected_injections})
        ctx.route = "security_event"
        return "Possible prompt injection detected."

    # 3. Domain Specific Compliance Rule
    prohibited_keywords = ["sell customer data", "selling data to third parties", "monetize personal data"]
    detected_prohibited = [kw for kw in prohibited_keywords if kw in node_input.lower()]

    if detected_prohibited:
        log_audit("compliance_prohibited_practice", "CRITICAL", {
            "detected_practices": detected_prohibited,
            "message": "Policy draft contains prohibited user data monetization practices."
        })
        ctx.route = "security_event"
        return "Compliance violation: Prohibited data selling practices detected in policy draft."

    log_audit("checkpoint_passed", "INFO", {})
    ctx.route = "clean"
    return redacted

@node
async def security_event_handler(ctx: Context, node_input: str):
    logs = list(ctx.state.get("audit_logs", []))
    logs.append(f"Security event handler invoked: {node_input}")
    ctx.state["audit_logs"] = logs
    return {
        "status": "REJECTED_SECURITY_VIOLATION",
        "details": node_input,
        "audit_logs": ctx.state.get("audit_logs", [])
    }

@node(rerun_on_resume=True)
async def compliance_analysis(ctx: Context, node_input: str):
    logs = list(ctx.state.get("audit_logs", []))
    logs.append("Starting compliance analysis.")
    ctx.state["audit_logs"] = logs
    
    # Run orchestrator dynamically
    report = await ctx.run_node(compliance_orchestrator, node_input=node_input)
    ctx.state["orchestrator_report"] = report
    
    logs = list(ctx.state.get("audit_logs", []))
    logs.append("Compliance report compiled by orchestrator.")
    ctx.state["audit_logs"] = logs

    # Check if edits are suggested in the report
    lower_report = report.lower()
    if "no policy edits are required" in lower_report or "no edits are required" in lower_report or "no edits suggested" in lower_report or "no policy edits required" in lower_report:
        needs_review = False
    else:
        needs_review = "suggested edits" in lower_report or "policy edit" in lower_report or "revision" in lower_report or "suggested policy edits" in lower_report
    
    if needs_review:
        ctx.state["suggests_edits"] = True
        logs = list(ctx.state.get("audit_logs", []))
        logs.append("Policy edits suggested; routing to manual compliance officer review.")
        ctx.state["audit_logs"] = logs
        ctx.route = "needs_review"
    else:
        ctx.state["suggests_edits"] = False
        logs = list(ctx.state.get("audit_logs", []))
        logs.append("No edits suggested; routing to auto-approval.")
        ctx.state["audit_logs"] = logs
        ctx.route = "auto_approved"

    return report

@node(rerun_on_resume=True)
async def request_approval(ctx: Context, node_input: Any):
    interrupt_id = "approve_policy_edits"
    
    if ctx.resume_inputs and interrupt_id in ctx.resume_inputs:
        response = ctx.resume_inputs[interrupt_id]
        approved = getattr(response, "approved", None)
        if approved is None:
            approved = response.get("approved", False) if isinstance(response, dict) else False
        comments = getattr(response, "comments", "")
        if not comments and isinstance(response, dict):
            comments = response.get("comments", "")

        ctx.state["approved"] = approved
        ctx.state["comments"] = comments
        
        logs = list(ctx.state.get("audit_logs", []))
        logs.append(f"Human review complete. Approved: {approved}. Comments: {comments}")
        ctx.state["audit_logs"] = logs
        
        yield f"Officer decision registered: {'Approved' if approved else 'Rejected'}"
        return

    logs = list(ctx.state.get("audit_logs", []))
    logs.append("Awaiting compliance officer approval.")
    ctx.state["audit_logs"] = logs
    
    yield RequestInput(
        interrupt_id=interrupt_id,
        message="Suggested policy edits require compliance officer review. Please approve or reject.",
        response_schema=ApproveResponse
    )

@node
async def final_approval(ctx: Context, node_input: Any):
    suggested = ctx.state.get("suggests_edits", False)
    if suggested:
        approved = ctx.state.get("approved", False)
        status = "APPROVED" if approved else "REJECTED"
    else:
        status = "AUTO_APPROVED"
        
    logs = list(ctx.state.get("audit_logs", []))
    logs.append(f"Final workflow outcome: {status}")
    ctx.state["audit_logs"] = logs
    
    return {
        "original_input": ctx.state.get("original_input", ""),
        "sanitized_input": ctx.state.get("sanitized_input", ""),
        "compliance_report": ctx.state.get("orchestrator_report", ""),
        "status": status,
        "human_reviewed": suggested,
        "comments": ctx.state.get("comments", ""),
        "audit_logs": ctx.state.get("audit_logs", [])
    }

# ---------------------------------------------------------------------------
# Workflow Edge Definition
# ---------------------------------------------------------------------------

edges = [
    Edge(from_node=START, to_node=security_checkpoint),
    Edge(from_node=security_checkpoint, to_node=compliance_analysis, route="clean"),
    Edge(from_node=security_checkpoint, to_node=security_event_handler, route="security_event"),
    Edge(from_node=compliance_analysis, to_node=request_approval, route="needs_review"),
    Edge(from_node=compliance_analysis, to_node=final_approval, route="auto_approved"),
    Edge(from_node=request_approval, to_node=final_approval)
]

root_agent = Workflow(
    name="compliance_tracker_workflow",
    edges=edges,
    state_schema=ComplianceState
)

# ---------------------------------------------------------------------------
# App Initialization
# ---------------------------------------------------------------------------

app = App(
    root_agent=root_agent,
    name="app",
)
