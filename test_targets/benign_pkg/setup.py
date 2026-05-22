from setuptools import setup, find_packages

setup(
    name="benign-math-pkg",
    version="1.0.0",
    description="A safe and benign package that performs basic mathematical operations",
    author="TraceTree Tester",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
)
