import sys

from setuptools import setup, find_packages

import versioneer


needs_pytest = {"pytest", "test", "ptr", "coverage"}.intersection(sys.argv)
pytest_runner = ["pytest-runner"] if needs_pytest else []

setup(
    name = "c4-policyengine",
    version = versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    packages = find_packages(),
    install_requires = ["c4-systemmanager", "c4-utils"],
    setup_requires=[] + pytest_runner,
    tests_require=["pytest", "pytest-cov"],
    author = "IBM",
    author_email = "",
    description = "This is a collection of policy engine modules for project C4",
    license = "IBM",
    keywords = "python c4 policy engine",
    url = "",
)
