from setuptools import setup, find_packages

with open("readme.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="modular-reconx",
    version="1.3.0",
    author="Reynov Christian",
    author_email="contact@chrisnov.com",
    description="A modular OSINT tool for performing complete analysis of domains or websites using open-source intelligence techniques",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/chrisnov-it/modular_reconx",
    project_urls={
        "Bug Tracker": "https://github.com/chrisnov-it/modular_reconx/issues",
        "Documentation": "https://github.com/chrisnov-it/modular_reconx#readme",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet",
        "Topic :: Utilities",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ],
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "reconx=app.scan:main",
            "modular-reconx=app.scan:main",
        ],
    },
    package_data={
        "app": ["data/*"],
    },
    data_files=[
        ("data", ["app/data/subdomains.txt", "app/data/common_paths.txt"]),
    ],
)