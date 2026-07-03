from setuptools import setup, find_packages

setup(
    name="cryptopals",
    version="1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    extras_require={
        "dev": ["pytest", "pycryptodome"]
    }
)
