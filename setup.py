# setup.py
from setuptools import setup, find_packages

setup(
    name="fda_snitch",
    version="0.2.1",
    description="Tamper-evident exam-integrity monitor: connectivity and clipboard logging with a verifiable hash chain",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Casper Kaandorp",
    author_email="casper@compunist.nl",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)