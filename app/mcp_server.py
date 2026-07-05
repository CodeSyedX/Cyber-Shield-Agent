import os
import re
import json
import logging
from typing import List, Dict, Any
from mcp.server.fastmcp import FastMCP

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cyber-shield-mcp")

# Initialize FastMCP Server
mcp = FastMCP("cyber-shield-mcp")

# Mock database of package vulnerabilities
VULNERABILITY_DB = {
    "requests": [
        {"cve": "CVE-2023-32681", "severity": "HIGH", "description": "Leaking Proxy-Authorization headers on redirect.", "fixed_in": "2.31.0"}
    ],
    "urllib3": [
        {"cve": "CVE-2023-43804", "severity": "HIGH", "description": "Cookie leakage on cross-origin redirects.", "fixed_in": "2.0.6"},
        {"cve": "CVE-2024-37891", "severity": "MEDIUM", "description": "Proxy-Authorization header leakage on redirects.", "fixed_in": "2.2.2"}
    ],
    "django": [
        {"cve": "CVE-2023-43665", "severity": "CRITICAL", "description": "ReDoS in django.utils.html.strip_tags.", "fixed_in": "4.2.6"}
    ]
}

@mcp.tool()
def regex_scanner(content: str) -> str:
    """Scans code content for common secret patterns using fast pre-defined regex.

    Args:
        content: The code content or text to scan.

    Returns:
        JSON string containing match status and specific secrets identified.
    """
    logger.info("MCP Tool: regex_scanner executed")
    patterns = {
        "Gemini API Key": r"AIzaSy[a-zA-Z0-9\-_]{33}",
        "Generic API Key": r"(?:key|api|token|secret|password|passwd|auth)(?:[^\n\r=<>]*=[^\n\r\"']*[\"'])([a-zA-Z0-9\-_]{16,})[\"']",
        "Private Key": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----",
    }
    
    findings = []
    for name, regex in patterns.items():
        matches = re.finditer(regex, content, re.IGNORECASE)
        for match in matches:
            findings.append({
                "type": name,
                "snippet": match.group(0)[:15] + "..." if len(match.group(0)) > 15 else match.group(0),
                "start": match.start(),
                "end": match.end()
            })
            
    return json.dumps({
        "matched": len(findings) > 0,
        "findings": findings
    })

@mcp.tool()
def check_cve_database(package_name: str, version: str) -> str:
    """Checks the local mock vulnerability database for known CVEs matching a library.

    Args:
        package_name: Name of the library/package.
        version: Version string (e.g. '2.28.1').

    Returns:
        JSON string containing vulnerability information or safe status.
    """
    logger.info(f"MCP Tool: check_cve_database executed for {package_name}@{version}")
    name_clean = package_name.lower().strip()
    
    if name_clean in VULNERABILITY_DB:
        vulns = []
        for v in VULNERABILITY_DB[name_clean]:
            # Simple version comparison check (for mock purposes, if version is lower than fixed_in)
            # In a real environment, we'd use packaging.version
            fixed = v["fixed_in"]
            # Basic fallback: if version != fixed, assume vulnerable for mock demonstration
            if version != fixed:
                vulns.append(v)
                
        if vulns:
            return json.dumps({
                "vulnerable": True,
                "package": package_name,
                "version": version,
                "vulnerabilities": vulns
            })
            
    return json.dumps({
        "vulnerable": False,
        "package": package_name,
        "version": version,
        "message": "No known vulnerabilities found in local database."
    })

@mcp.tool()
def audit_log_exporter(event_type: str, severity: str, log_data: str) -> str:
    """Exports structured security audit logs for compliance tracking.

    Args:
        event_type: The type of security event (e.g., 'secret_scan', 'pii_scrub', 'injection').
        severity: The severity level ('INFO', 'WARNING', 'CRITICAL').
        log_data: JSON-serialized details of the event.

    Returns:
        JSON string indicating log export success status.
    """
    logger.info(f"MCP Tool: audit_log_exporter [{severity}] {event_type}")
    log_entry = {
        "event_type": event_type,
        "severity": severity.upper(),
        "details": log_data
    }
    
    # In a real tool, we would write to a secure audit file or external SIEM
    # For now, we simulate success
    return json.dumps({
        "status": "logged",
        "entry": log_entry
    })

if __name__ == "__main__":
    mcp.run()
