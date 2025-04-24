from setuptools import setup, find_packages

setup(
    name="asana-warrior",
    version="0.1.0",
    description="Bidirectional sync between Asana and Taskwarrior",
    packages=find_packages(),
    install_requires=[
        "click",
        "appdirs",
        "requests",
        "requests-oauthlib",
        "taskw",
    ],
    entry_points={
        "console_scripts": [
            "asana-warrior=asana_warrior.cli:main",
            "aw=asana_warrior.cli:main",
            "awarrior=asana_warrior.cli:main",
        ],
    },
)
