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

            try:
                from playwright.sync_api import sync_playwright

                with sync_playwright() as p:
                    browser = p.chromium.connect_over_cdp(ws_url, headers=headers)
                    context = browser.contexts[0] if browser.contexts else browser.new_context()
                    page = context.new_page()

                    page.goto(url, wait_until="domcontentloaded", timeout=30000)

                    # Extract page content based on the instruction
                    title = page.title()
                    content = page.inner_text("body")

                    # Truncate content to avoid token limits
                    max_content_length = 10000
                    if len(content) > max_content_length:
                        content = content[:max_content_length] + "\n...[content truncated]"

                    page.close()
                    browser.close()

                    return json.dumps({
                        "status": "success",
                        "url": url,
                        "title": title,
                        "instruction": instruction,
                        "content": content,
                    })

            except ImportError:
                logger.warning("Playwright not installed. Returning browser session info.")
                return json.dumps({
                    "status": "playwright_not_available",
                    "url": url,
                    "instruction": instruction,
                    "ws_endpoint": ws_url[:50] + "...",
                    "message": (
                        "Browser session established but Playwright is not installed. "
                        "Install with: pip install playwright && playwright install chromium"
                    ),
                })

    except Exception as e:
        logger.error(f"Browser error: {e}")
        return f"Error browsing URL: {str(e)}"
