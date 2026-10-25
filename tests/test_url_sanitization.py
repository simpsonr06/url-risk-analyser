
import pytest

from database.queries import sanitize_url_for_history


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://alice:secret@example.com/path?token=abc123#section",
            "https://example.com/path",
        ),
        (
            "https://example.com:8443/login?next=private",
            "https://example.com:8443/login",
        ),
        (
            "https://example.com/path?api_key=secret",
            "https://example.com/path",
        ),
        (
            "https://example.com/path#private-fragment",
            "https://example.com/path",
        ),
        (
            "https://[2001:4860:4860::8888]:8443/path?token=secret",
            "https://[2001:4860:4860::8888]:8443/path",
        ),
    ],
)
def test_sanitize_url_for_history(url, expected):
    assert sanitize_url_for_history(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "not a valid URL",
        "",
        "example.com/path",
        "https://",
    ],
)
def test_invalid_url_is_redacted(url):
    assert sanitize_url_for_history(url) == "[redacted URL]"


def test_credentials_and_secrets_do_not_appear_in_output():
    url = (
        "https://alice:password123@example.com/login"
        "?token=secret456#private"
    )

    result = sanitize_url_for_history(url)

    assert "alice" not in result
    assert "password123" not in result
    assert "secret456" not in result
    assert "private" not in result
