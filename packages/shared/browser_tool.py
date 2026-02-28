"""AgentCore Browser wrapped as Strands @tool for cloud-based web automation."""
import os
import json
import logging

from strands import tool

logger = logging.getLogger(__name__)

REGION = os.getenv("AWS_REGION", "us-west-2")


@tool
def browse_url(url: str, instruction: str) -> str:
    """Browse a URL using AgentCore's cloud-based browser and extract information.

    Use this tool when you need to:
    - Scrape data from web pages (news, financial data, public records)
    - Research information on the internet
    - Check real-time information from websites
    - Fill forms or interact with web applications

    The browser runs in a secure, isolated cloud environment with full JavaScript support.

    Args:
        url: The URL to navigate to (must be a valid http/https URL).
        instruction: What information to extract or what action to perform on the page.

    Returns:
        Extracted text content or action results from the web page.
    """
    try:
        from bedrock_agentcore.tools import browser_session

        with browser_session(REGION) as client:
            ws_url, headers = client.generate_ws_headers()

            # Use Playwright to interact with the page
            # Note: In production, this would use the full Playwright integration
            # For the pattern, we return the connection info
            return json.dumps({
                "status": "browser_session_ready",
                "url": url,
                "instruction": instruction,
                "ws_endpoint": ws_url[:50] + "...",
                "message": "Browser session established. Use Playwright to interact with the page.",
            })
    except Exception as e:
        logger.error(f"Browser error: {e}")
        return f"Error browsing URL: {str(e)}"
