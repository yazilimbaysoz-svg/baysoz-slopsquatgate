"""Versioned curated baseline of high-prevalence package names. Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

ATTRIBUTION = "Baysöz Labs <baysozlabs@proton.me>"
BASELINE_VERSION = "2026-11-27"

BASELINE: dict[str, frozenset[str]] = {
    "pypi": frozenset(
        {
            "attrs", "boto3", "certifi", "click", "cryptography", "django", "fastapi",
            "flask", "httpx", "idna", "jinja2", "numpy", "opencv-python", "pandas",
            "pip", "pydantic", "pytest", "pyyaml", "requests", "ruff", "scipy",
            "semgrep", "setuptools", "sqlalchemy", "torch", "urllib3", "uvicorn",
            "wheel", "packaging", "typing-extensions", "opentelemetry-sdk",
        }
    ),
    "npm": frozenset(
        {
            "@types/node", "@types/react", "axios", "chalk", "commander", "dotenv",
            "eslint", "express", "fastify", "jsonwebtoken", "lodash", "next", "node-fetch",
            "prettier", "react", "react-dom", "semver", "tar", "typescript", "vite",
            "webpack", "zod", "@modelcontextprotocol/sdk", "@playwright/test",
        }
    ),
    "cargo": frozenset(
        {
            "anyhow", "bytes", "chrono", "clap", "dashmap", "futures", "http", "hyper",
            "log", "once_cell", "rand", "regex", "reqwest", "serde", "serde_json",
            "thiserror", "tokio", "toml", "tracing", "url", "uuid", "zeroize",
        }
    ),
    "go": frozenset(
        {
            "github.com/google/uuid", "github.com/pkg/errors", "github.com/spf13/cobra",
            "github.com/stretchr/testify", "golang.org/x/crypto", "golang.org/x/net",
            "golang.org/x/sys", "google.golang.org/grpc", "google.golang.org/protobuf",
            "gopkg.in/yaml.v3", "go.uber.org/zap", "github.com/prometheus/client_golang",
        }
    ),
}


def baseline_for(ecosystem: str) -> frozenset[str]:
    """Return the curated baseline for an ecosystem, or an empty set."""
    return BASELINE.get(ecosystem, frozenset())
