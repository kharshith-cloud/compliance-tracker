# ruff: noqa
import sys
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP Server
mcp = FastMCP("Regulatory Compliance MCP Server")

# Simulated in-memory database
POLICIES = {
    "gdpr": (
        "Internal Policy: Customer Personal Data Handling\n"
        "1. Consent: Customers must explicitly opt-in to marketing communications. Opt-in records must be stored.\n"
        "2. Data Retention: Customer data is retained for 7 years post-activity, then deleted/anonymized.\n"
        "3. Portability: Customers can request an export of their personal data via the portal, processed within 30 days."
    ),
    "hipaa": (
        "Internal Policy: Protected Health Information (PHI) Access Controls\n"
        "1. Authorization: Only authorized medical staff with valid credentials may access patient health records.\n"
        "2. Auditing: Every access to PHI must be logged with user ID, patient ID, and timestamp.\n"
        "3. Encryption: All PHI stored at rest must use AES-256 encryption, and in transit must use TLS 1.3."
    )
}

REGULATORY_FEEDS = {
    "gdpr": (
        "REGULATORY UPDATE (GDPR Article 17): Emphasis on the Right to Erasure ('Right to be forgotten'). "
        "Organizations must ensure that data subject requests for deletion are fully executed across all sub-processors "
        "and backups within 30 days. Consent must be granular, and generic opt-ins are no longer valid."
    ),
    "hipaa": (
        "REGULATORY UPDATE (HIPAA Security Rule): Standardizing access controls. Multi-factor authentication (MFA) "
        "is now mandatory for all remote access systems processing PHI. Incident response reporting window is reduced "
        "to 72 hours for significant breaches."
    )
}

@mcp.tool()
def get_company_policy(policy_type: str) -> str:
    """Retrieve the current company policy draft for GDPR or HIPAA.
    
    Args:
        policy_type: The policy type to retrieve. Must be 'gdpr' or 'hipaa'.
    """
    pt = policy_type.lower().strip()
    if pt not in POLICIES:
        return f"Error: Policy for '{policy_type}' not found. Available policies: {list(POLICIES.keys())}"
    return POLICIES[pt]

@mcp.tool()
def update_company_policy(policy_type: str, new_content: str) -> str:
    """Update and save the company policy content for GDPR or HIPAA.
    
    Args:
        policy_type: The policy type to update. Must be 'gdpr' or 'hipaa'.
        new_content: The new policy draft content.
    """
    pt = policy_type.lower().strip()
    if pt not in POLICIES:
        return f"Error: Cannot update. Policy for '{policy_type}' not found."
    POLICIES[pt] = new_content
    return f"Success: Policy for '{policy_type}' updated successfully."

@mcp.tool()
def fetch_regulatory_feed(regulation_type: str) -> str:
    """Fetch the latest official regulatory updates and feeds for GDPR or HIPAA.
    
    Args:
        regulation_type: The regulation type to fetch feed for. Must be 'gdpr' or 'hipaa'.
    """
    rt = regulation_type.lower().strip()
    if rt not in REGULATORY_FEEDS:
        return f"Error: Regulatory feed for '{regulation_type}' not found."
    return REGULATORY_FEEDS[rt]

if __name__ == "__main__":
    # Start the server (stdio transport by default)
    mcp.run()
