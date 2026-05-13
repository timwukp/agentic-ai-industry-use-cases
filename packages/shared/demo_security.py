"""Demo: DevSecOps workflow trigger test.

This file demonstrates that all security scanning workflows
are triggered correctly on PR creation.
"""


def validate_input(user_input: str) -> str:
    """Sanitize user input - demonstrates secure coding pattern."""
    if not isinstance(user_input, str):
        raise TypeError("Input must be a string")
    # Strip potential injection characters
    sanitized = user_input.replace("<", "&lt;").replace(">", "&gt;")
    return sanitized.strip()[:1000]
