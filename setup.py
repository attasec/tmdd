#!/usr/bin/env python3
"""TMDD - Threat Modeling Driven Development. Install: pip install ."""
from setuptools import setup, find_packages
from pathlib import Path

readme = Path(__file__).parent / "README.md"
long_desc = readme.read_text(encoding="utf-8") if readme.exists() else ""

setup(
    name="tmdd",
    version="0.5.0",
    description="Threat Modeling Driven Development - YAML-based threat modeling framework",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    author="mik0w",
    license="MIT",
    packages=find_packages(),
    py_modules=["diagram", "report"],
    include_package_data=True,
    package_data={"src": ["templates/**/*.yaml", "tmdd.schema.json"]},
    install_requires=["PyYAML>=6.0"],
    extras_require={
        "dev": ["pytest", "black", "mypy"],
    },
    entry_points={
        "console_scripts": [
            "tmdd=src.cli:main",
            "tmdd-diagram=diagram:main",
            "tmdd-report=report:main",
        ]
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    keywords="security, threat-modeling, yaml, devsecops",
)
