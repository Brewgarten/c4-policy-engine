from setuptools import setup, find_packages

import versioneer


setup(
    name = "c4-policyengine",
    version = versioneer.get_version(),
    cmdclass=versioneer.get_cmdclass(),
    packages = find_packages(),
    install_requires = ["c4-system", "c4-utils"],
    author = "IBM",
    author_email = "",
    description = "This is a collection of policy engine modules for project C4",
    license = "IBM",
    keywords = "python c4 policy engine",
    url = "",
)
