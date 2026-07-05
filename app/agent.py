import os
import re
import json
import logging
from typing import List, Optional, Any
from pydantic import BaseModel, Field

from google.adk.agents import Agent, LlmAgent
from google.adk.workflow import Workflow, START, node, FunctionNode
from google.adk.agents.context import Context
from google.adk.events.event import Event
from google.adk.events.request_input import RequestInput
from google.adk.tools import AgentTool
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters
from google.adk.apps import App, ResumabilityConfig
from google.genai import types

from app.config import config

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cyber-shield-agent")

# Define Data Schemas
class Finding(BaseModel):
    type: str = Field(..., description="Type of finding: 'secret' or 'vulnerability'.")
    severity: str = Field(..., description="Severity of the finding: 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'.")
    description: str = Field(..., description="Description of the security issue found.")
    remediation: str = Field(..., description="Suggested remediation action.")

class ScannerOutput(BaseModel):
    findings: List[Finding] = Field(default_factory=list, description="List of security findings.")
    high_severity_found: bool = Field(False, description="True if any HIGH or CRITICAL severity findings exist.")

# Helpers
def extract_text(node_input: Any) -> str:
    if isinstance(node_input, str):
        return node_input
    if hasattr(node_input, "parts") and node_input.parts:
        return "".join([part.text for part in node_input.parts if part.text])
    if isinstance(node_input, dict):
        return node_input.get("text", "")
    return str(node_input)

# Stdio Connection to Local MCP Server
mcp_toolset = McpToolset(
    connection_params=StdioConnectionParams(
        server_params=StdioServerParameters(
            command="uv",
            args=["run", "python", "app/mcp_server.py"],
        ),
    )
)

# Sub-Agents
secret_scanner = LlmAgent(
    name="secret_scanner",
    model=config.model,
    instruction="""You are a specialized security agent. Analyze the provided source code for exposed secrets (e.g. API keys, credentials, private keys, passwords, database URLs, auth tokens).
You have access to an MCP Toolset. Use the 'regex_scanner' tool from the MCP Toolset to run regex scans over the code to identify exposed keys first.
Return the results matching the ScannerOutput schema. Set high_severity_found to True if there are any secrets found, since exposed secrets are always high severity (HIGH or CRITICAL).
""",
    tools=[mcp_toolset],
    output_schema=ScannerOutput,
    description="Analyzes code content to identify exposed secrets, private keys, and API tokens.",
)

vuln_analyzer = LlmAgent(
    name="vuln_analyzer",
    model=config.model,
    instruction="""You are a specialized dependency vulnerability scanner. Examine the user's packages/dependencies list or files (like requirements.txt, package.json, or list of package names) for known package vulnerabilities.
You have access to an MCP Toolset. Use the 'check_cve_database' tool from the MCP Toolset to verify CVEs for specific packages and package versions.
Determine the severity, description of the vulnerability, and upgrade/remediation path.
Return the results matching the ScannerOutput schema. If there are packages with known critical or high CVEs, set high_severity_found to True.
""",
    tools=[mcp_toolset],
    output_schema=ScannerOutput,
    description="Scans a list of package dependencies and library versions for known CVE vulnerabilities.",
)

# Orchestrator
orchestrator = LlmAgent(
    name="orchestrator",
    model=config.model,
    instruction="""You are the security orchestration agent.
The user wants to perform a security scan on code, dependencies, or both.
1. Check the user input.
2. If code content is provided, call the 'secret_scanner' using the secret_scanner tool to scan for secrets.
3. If packages or dependencies are provided, call the 'vuln_analyzer' using the vuln_analyzer tool to check for vulnerabilities.
4. If the input is ambiguous but looks like code, run it through the secret_scanner.
5. Combine findings from all sub-agents that you invoke. Ensure high_severity_found is True if either scanner found high-severity issues.
6. Provide a consolidated ScannerOutput list of findings.
""",
    tools=[AgentTool(secret_scanner), AgentTool(vuln_analyzer)],
    output_schema=ScannerOutput,
    output_key="findings",
    description="Orchestrates security scans by routing requests to the secret scanner and vulnerability analyzer.",
)

# Workflow Function Nodes

def security_checkpoint(ctx: Context, node_input: Any) -> Event:
    """Security check node enforcing PII scrubbing, injection prevention, and payload size bounds."""
    user_text = extract_text(node_input)
    pii_scrubbed = False
    injection_detected = False
    
    # Domain-specific rule: Content size filter (max 10,000 characters)
    if len(user_text) > 10000:
        audit_log = {
            "event": "security_checkpoint_violation",
            "reason": "Input length exceeded limit (10,000 characters)",
            "input_length": len(user_text),
            "severity": "WARNING"
        }
        logger.warning(json.dumps(audit_log))
        msg = f"⚠️ Security Policy Violation: Scan input length ({len(user_text)} characters) exceeds the maximum allowed limit of 10,000 characters."
        content = types.Content(role="model", parts=[types.Part.from_text(text=msg)])
        return Event(output={"error": msg}, route="SECURITY_EVENT", content=content)

    # PII Scrubbing (Emails and Phone Numbers)
    email_regex = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    phone_regex = r"\b(?:\+?\d{1,3}[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b"
    
    if re.search(email_regex, user_text):
        user_text = re.sub(email_regex, "[REDACTED_EMAIL]", user_text)
        pii_scrubbed = True
        
    if re.search(phone_regex, user_text):
        user_text = re.sub(phone_regex, "[REDACTED_PHONE]", user_text)
        pii_scrubbed = True

    # Prompt Injection Detection
    injection_keywords = [
        "ignore previous instructions", 
        "bypass security", 
        "override scanner", 
        "system prompt", 
        "you are now a helpful assistant",
        "do not scan"
    ]
    
    for kw in injection_keywords:
        if kw in user_text.lower():
            injection_detected = True
            break
            
    if injection_detected:
        audit_log = {
            "event": "prompt_injection_detected",
            "input_snippet": user_text[:100],
            "severity": "CRITICAL"
        }
        logger.error(json.dumps(audit_log))
        msg = "⚠️ Security Policy Violation: Potential prompt injection attempt detected."
        content = types.Content(role="model", parts=[types.Part.from_text(text=msg)])
        return Event(output={"error": msg}, route="SECURITY_EVENT", content=content)

    # Normal check log
    audit_log = {
        "event": "security_checkpoint_passed",
        "pii_scrubbed": pii_scrubbed,
        "input_length": len(user_text),
        "severity": "INFO"
    }
    logger.info(json.dumps(audit_log))

    return Event(output=user_text)

def security_event_handler(ctx: Context, node_input: Any) -> Event:
    """Handles requests blocked by security checkpoint."""
    # Predecessor output will be the blocked error dict from security_checkpoint
    error_msg = node_input.get("error", "⚠️ Security Policy Violation: Request blocked.")
    content = types.Content(role="model", parts=[types.Part.from_text(text=error_msg)])
    return Event(output={"error": error_msg}, content=content)

async def review_gate(ctx: Context, node_input: Any) -> Event:
    """HITL step: Requests user approval if high severity security findings exist."""
    findings_dict = ctx.state.get("findings", {})
    high_severity_found = findings_dict.get("high_severity_found", False)
    
    if high_severity_found:
        if not ctx.resume_inputs or "user_approval" not in ctx.resume_inputs:
            yield RequestInput(
                interrupt_id="user_approval",
                message="⚠️ High-severity security issues detected! Please review the findings and reply 'approve' to generate the threat report, or 'cancel' to abort."
            )
            return
        
        user_reply = ctx.resume_inputs["user_approval"]
        if "approve" not in user_reply.lower():
            msg = "❌ Report generation cancelled by user approval denial."
            content = types.Content(role="model", parts=[types.Part.from_text(text=msg)])
            yield Event(output={"status": "denied", "message": msg}, content=content)
            return

    yield Event(output={"status": "approved"}, state={"approved": True})

def generate_report(ctx: Context, node_input: Any) -> Event:
    """Formats findings into a comprehensive Markdown threat report."""
    findings_dict = ctx.state.get("findings", {})
    findings = findings_dict.get("findings", [])
    high_severity_found = findings_dict.get("high_severity_found", False)
    
    # Calculate overall risk score
    score = 0
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev == "CRITICAL":
            score += 40
        elif sev == "HIGH":
            score += 25
        elif sev == "MEDIUM":
            score += 10
        else:
            score += 5
    score = min(score, 100)
    
    report_md = "# 🛡️ Cyber Shield Threat Report\n\n"
    report_md += f"**Overall Risk Score:** `{score}/100`\n"
    if high_severity_found:
        report_md += "⚠️ **Status:** ACTION REQUIRED (High severity issues detected)\n\n"
    else:
        report_md += "✅ **Status:** SECURE (No high severity issues detected)\n\n"
        
    report_md += "## Executive Summary\n"
    if not findings:
        report_md += "The security scan found no secrets or package vulnerabilities. Your project meets basic security compliance.\n"
    else:
        report_md += f"The scan detected {len(findings)} security findings. Please review the breakdown and remediation steps below.\n\n"
        report_md += "## Findings & Remediation\n"
        for i, f in enumerate(findings, 1):
            report_md += f"### {i}. [{f.get('severity')}] {f.get('type').title()}\n"
            report_md += f"- **Description:** {f.get('description')}\n"
            report_md += f"- **Remediation:** {f.get('remediation')}\n\n"
            
    content = types.Content(role="model", parts=[types.Part.from_text(text=report_md)])
    return Event(output={"report": report_md}, content=content)

# Workflow Graph Definition
root_agent = Workflow(
    name="cyber_shield_workflow",
    edges=[
        (START, security_checkpoint),
        (security_checkpoint, {
            "__DEFAULT__": orchestrator,
            "SECURITY_EVENT": security_event_handler
        }),
        (orchestrator, review_gate),
        (review_gate, generate_report),
    ],
    description="Secures development by scanning for secrets and package vulnerabilities, routing reports, and managing human approvals.",
)

# App Container
app = App(
    name="app",
    root_agent=root_agent,
    resumability_config=ResumabilityConfig(is_resumable=True),
)
