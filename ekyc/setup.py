"""
Setup configuration for the Next-Generation eKYC System.

This module provides the packaging configuration for distributing
the eKYC system as a Python package.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = [
        line.strip()
        for line in requirements_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

# Core dependencies (exclude dev dependencies for install_requires)
install_requires = [
    req for req in requirements
    if not any(pkg in req.lower() for pkg in ["pytest", "moto", "httpx"])
]

# Dev dependencies
dev_requires = [
    "pytest>=7.4.0",
    "pytest-asyncio>=0.23.0",
    "pytest-cov>=4.1.0",
    "moto>=4.2.0",
    "httpx>=0.26.0",
    "black>=23.0.0",
    "ruff>=0.1.0",
    "mypy>=1.8.0",
    "pre-commit>=3.6.0",
]

# Documentation dependencies
docs_requires = [
    "mkdocs>=1.5.0",
    "mkdocs-material>=9.5.0",
    "mkdocstrings[python]>=0.24.0",
]

setup(
    name="ekyc-system",
    version="0.1.0",
    author="eKYC Team",
    author_email="ekyc-team@example.com",
    description="Next-Generation eKYC System with multi-agent architecture for digital identity verification",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/agentic-ai-industry-use-cases/tree/main/ekyc",
    project_urls={
        "Bug Reports": "https://github.com/your-org/agentic-ai-industry-use-cases/issues",
        "Documentation": "https://github.com/your-org/agentic-ai-industry-use-cases/tree/main/ekyc/docs",
        "Source": "https://github.com/your-org/agentic-ai-industry-use-cases/tree/main/ekyc",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Financial and Insurance Industry",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Framework :: FastAPI",
        "Environment :: Web Environment",
    ],
    python_requires=">=3.10",
    install_requires=install_requires,
    extras_require={
        "dev": dev_requires,
        "docs": docs_requires,
        "all": dev_requires + docs_requires,
    },
    entry_points={
        "console_scripts": [
            "ekyc-server=src.api.routes:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        "ekyc",
        "kyc",
        "identity-verification",
        "biometric",
        "compliance",
        "fraud-detection",
        "aws",
        "bedrock",
        "agents",
        "multi-agent",
    ],
)
