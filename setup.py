"""Setup script for NetSentinel."""

from setuptools import setup, find_packages
from pathlib import Path

# Read long description from README
readme_path = Path(__file__).parent / "README.md"
if readme_path.exists():
    with open(readme_path, "r", encoding="utf-8") as fh:
        long_description = fh.read()
else:
    long_description = ""

# Requirements are defined in pyproject.toml - don't read requirements.txt
# since it may not exist and pyproject.toml is the source of truth
setup(
    name="netsentinel",
    version="0.1.0",
    author="NetSentinel Team",
    description="Network Security Auditing Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.10",
    # install_requires is read from pyproject.toml automatically
    entry_points={
        "console_scripts": [
            "netsentinel=netsentinel.cli:main",
            "nts=netsentinel.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
    ],
)
