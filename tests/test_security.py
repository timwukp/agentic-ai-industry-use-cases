"""Tests for packages/shared/security.py - input validation, sanitization, and redaction."""
from packages.shared.security import validate_input, sanitize_input, redact_sensitive_data


class TestValidateInput:
    """Tests for validate_input function."""

    def test_empty_string_returns_false(self):
        is_valid, msg = validate_input("")
        assert is_valid is False
        assert "empty" in msg.lower()

    def test_whitespace_only_returns_false(self):
        is_valid, msg = validate_input("   ")
        assert is_valid is False
        assert "empty" in msg.lower()

    def test_too_long_string_returns_false(self):
        is_valid, msg = validate_input("a" * 10001)
        assert is_valid is False
        assert "max" in msg.lower() or "length" in msg.lower()

    def test_custom_max_length(self):
        is_valid, msg = validate_input("hello", max_length=3)
        assert is_valid is False
        assert "length" in msg.lower()

    def test_eval_injection_detected(self):
        is_valid, msg = validate_input("eval(something)")
        assert is_valid is False
        assert "unsafe" in msg.lower()

    def test_exec_injection_detected(self):
        is_valid, msg = validate_input("exec(code)")
        assert is_valid is False
        assert "unsafe" in msg.lower()

    def test_script_tag_detected(self):
        is_valid, msg = validate_input('<script>alert("xss")</script>')
        assert is_valid is False
        assert "unsafe" in msg.lower()

    def test_sql_injection_union_select(self):
        is_valid, msg = validate_input("1 UNION SELECT * FROM users")
        assert is_valid is False
        assert "unsafe" in msg.lower()

    def test_sql_injection_or_1_equals_1(self):
        is_valid, msg = validate_input("admin' or 1=1 --")
        assert is_valid is False
        assert "unsafe" in msg.lower()

    def test_path_traversal_detected(self):
        is_valid, msg = validate_input("../../etc/passwd")
        assert is_valid is False
        assert "unsafe" in msg.lower()

    def test_valid_input_returns_true(self):
        is_valid, msg = validate_input("What is the stock price of AAPL?")
        assert is_valid is True
        assert msg == ""

    def test_valid_input_with_numbers(self):
        is_valid, msg = validate_input("Show me the top 10 stocks by volume")
        assert is_valid is True
        assert msg == ""


class TestSanitizeInput:
    """Tests for sanitize_input function."""

    def test_removes_null_bytes(self):
        result = sanitize_input("hello\x00world")
        assert "\x00" not in result
        assert result == "helloworld"

    def test_removes_control_characters(self):
        result = sanitize_input("hello\x01\x02\x03world")
        assert result == "helloworld"

    def test_preserves_newlines(self):
        result = sanitize_input("hello\nworld")
        assert result == "hello\nworld"

    def test_preserves_tabs(self):
        result = sanitize_input("hello\tworld")
        assert result == "hello\tworld"

    def test_strips_whitespace(self):
        result = sanitize_input("  hello world  ")
        assert result == "hello world"


class TestRedactSensitiveData:
    """Tests for redact_sensitive_data function."""

    def test_redacts_credit_card_with_dashes(self):
        result = redact_sensitive_data("My card is 4111-1111-1111-1111")
        assert "[REDACTED_CARD]" in result
        assert "4111" not in result

    def test_redacts_credit_card_with_spaces(self):
        result = redact_sensitive_data("Card: 4111 1111 1111 1111")
        assert "[REDACTED_CARD]" in result

    def test_redacts_ssn(self):
        result = redact_sensitive_data("SSN is 123-45-6789")
        assert "[REDACTED_SSN]" in result
        assert "123-45-6789" not in result

    def test_redacts_password(self):
        result = redact_sensitive_data("password=secret123")
        assert "[REDACTED_CREDENTIAL]" in result
        assert "secret123" not in result

    def test_redacts_api_key(self):
        result = redact_sensitive_data("api_key=abc123xyz")
        assert "[REDACTED_CREDENTIAL]" in result

    def test_preserves_non_sensitive_text(self):
        text = "The stock price is $150.25"
        result = redact_sensitive_data(text)
        assert result == text
