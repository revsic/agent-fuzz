import json
from dataclasses import dataclass, asdict
from typing import TextIO

import yaml


@dataclass
class Config:
    """Configurations for harness generation"""

    # the name of the project.
    name: str
    # a path to the source code directory.
    srcdir: str
    # postfix for retrieve the source files form the source code directory.
    postfix: str | tuple | None = None
    # a path to the corpus directory.
    corpus_dir: str | None = None
    # a path to the dictionay file.
    fuzzdict: str | None = None
    # combination length, tuple of minimal and maximal length.
    comblen: tuple[int, int] = (5, 10)
    # maximum api lengths.
    max_apis: int = 200
    # the name of the llm.
    llm: str = "gpt-4o-mini-2024-07-18"
    # file extension for the generated harness.
    ext: str = ""
    # the maximum running time of fuzzer stage on harness generation, in seconds. (coverage-growth check)
    timeout: float = 600
    timeout_unit: float = 60
    # a limit for LLM API billing, in dollars.
    quota: float = 10

    @classmethod
    def load_from_yaml(cls, path: str):
        """Load a configuration from the given yaml file.
        Args:
            path: a path to the yaml file.
        Returns:
            the loaded configuration.
        """
        with open(path) as f:
            loaded = yaml.safe_load(f)
        return cls(**loaded)

    def dump(self, f: TextIO):
        """Dump the project to the yaml file.
        Args:
            f: writing stream.
        """
        yaml.safe_dump(asdict(self), f)

    @classmethod
    def load_from_json(cls, path: str):
        """Load a configuraiton from the given json file.
        Args:
            path: a path to the json file.
        Returns;
            the loaded configuration.
        """
        with open(path) as f:
            loaded = json.load(f)
        return cls(**loaded)
