# setup.py
from setuptools import setup, find_packages

setup(
    name="fda_snitch",
    version="0.1.2",
    description="FDA Snitch package ",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Casper Kaandorp",
    author_email="casper@compunist.nl",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "fda_snitch": ["assets/*.wav"],
    },
    install_requires=[
        "simpleaudio"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)