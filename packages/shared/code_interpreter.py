"""AgentCore Code Interpreter wrapped as Strands @tool for sandboxed code execution."""
import os
import json
import logging

from strands import tool

logger = logging.getLogger(__name__)

REGION = os.getenv("AWS_REGION", "us-west-2")


@tool
def execute_python_code(code: str) -> str:
    """Execute Python code in a secure, sandboxed AgentCore Code Interpreter environment.

    Use this tool when you need to:
    - Perform mathematical calculations or statistical analysis
    - Process or transform data using pandas, numpy, scipy
    - Generate charts or visualizations
    - Run machine learning models or simulations
    - Execute any Python code that requires a safe sandbox

    The sandbox has access to common scientific Python packages including
    numpy, pandas, scipy, scikit-learn, and matplotlib.

    Args:
        code: Python code to execute. Must be valid Python 3.10+ syntax.

    Returns:
        The output (stdout) of the executed code, or an error message if execution failed.
    """
    try:
        from bedrock_agentcore.tools import code_session

        with code_session(REGION) as client:
            result = client.execute_code(code)
            output = result.get("output", "") if isinstance(result, dict) else str(result)
            return output if output else "Code executed successfully (no output)."
    except ImportError:
        return "Error: bedrock-agentcore SDK not installed. Install with: pip install bedrock-agentcore"
    except Exception as e:
        logger.error(f"Code Interpreter error: {e}")
        return f"Error executing code: {str(e)}"


@tool
def install_and_run(packages: str, code: str) -> str:
    """Install Python packages and then execute code in the AgentCore Code Interpreter sandbox.

    Use this tool when you need packages beyond the standard set (numpy, pandas, scipy, etc.).

    Args:
        packages: Comma-separated list of pip package names to install (e.g., "yfinance,ta-lib").
        code: Python code to execute after package installation.

    Returns:
        The output of the executed code, or an error message.
    """
    try:
        from bedrock_agentcore.tools import code_session

        package_list = [p.strip() for p in packages.split(",") if p.strip()]

        with code_session(REGION) as client:
            if package_list:
                client.install_packages(package_list)
            result = client.execute_code(code)
            output = result.get("output", "") if isinstance(result, dict) else str(result)
            return output if output else "Code executed successfully (no output)."
    except Exception as e:
        logger.error(f"Code Interpreter error: {e}")
        return f"Error: {str(e)}"
