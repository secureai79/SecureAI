import ipaddress
import os
from urllib.parse import urlparse, urlunparse


def allow_local_repos() -> bool:
    return os.environ.get("ALLOW_LOCAL_REPOS", "false").lower() in {"1", "true", "yes", "on"}


def validate_repository_url(repo_url: str) -> str:
    """Accept canonical HTTPS GitHub URLs, or local file URLs in development."""
    value = (repo_url or "").strip()

    # Local repositories are permitted only when explicitly enabled.
    # Check this before parsed.netloc because Windows paths such as
    # file://C:\path\to\repo can be parsed with "C:" as the netloc.
    if value.lower().startswith("file://"):
        if not allow_local_repos():
            raise ValueError(
                "Local repositories are disabled. "
                "Set ALLOW_LOCAL_REPOS=true for local development only."
            )

        local_path = value[len("file://"):].strip()
        if not local_path:
            raise ValueError("Local repository path must not be empty")
        if "\x00" in local_path:
            raise ValueError("Invalid local repository path")

        return value

    parsed = urlparse(value)

    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Repository URL must be an HTTPS GitHub URL")

    if parsed.username or parsed.password:
        raise ValueError("Repository URLs containing credentials are not allowed")

    if (
        parsed.scheme.lower() != "https"
        or (parsed.hostname or "").lower()
        not in {"github.com", "www.github.com"}
    ):
        raise ValueError("Only HTTPS GitHub repository URLs are supported")

    if parsed.query or parsed.fragment:
        raise ValueError(
            "Repository URLs must not contain query parameters or fragments"
        )

    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) != 2:
        raise ValueError(
            "GitHub repository URL must look like "
            "https://github.com/owner/repository"
        )

    owner, repo = parts

    if any(c in owner + repo for c in ["\\", "\x00"]):
        raise ValueError("Invalid GitHub repository path")

    if repo.endswith(".git"):
        repo = repo[:-4]

    if not owner or not repo:
        raise ValueError("Invalid GitHub repository path")

    return urlunparse(
        ("https", "github.com", f"/{owner}/{repo}.git", "", "", "")
    )