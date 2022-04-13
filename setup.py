from setuptools import setup, find_packages

# python setup.py sdist
setup(
    name="password_validators",
    version="0.1",
    description="Collection of password validators",
    author="Rafał Buczyński",
    packages=["password_validators", "password_validators.exceptions"],
    install_requires=["requests", "PyYAML"],
)
