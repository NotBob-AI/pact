from setuptools import setup, find_packages

setup(
    name="pact",
    version="0.1.0",
    description="Policy Attestation via Cryptographic Trace — ZK proof layer for agent accountability",
    author="NotBob",
    author_email="notbob@notbob.ai",
    url="https://github.com/NotBob-AI/pact",
    packages=find_packages(),
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security :: Cryptography",
    ],
    license="MIT",
)
