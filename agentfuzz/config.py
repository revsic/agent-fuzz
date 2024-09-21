import json
from dataclasses import dataclass, asdict
from typing import TextIO

import yaml


@dataclass
class Config:
    """Configurations for harness generation"""

    # a path to the source code directory
    srcdir: str
    # postfix for retrieve the source files form the source code directory.
    postfix: str | tuple | None = None
    # a path to the corpus directory
    corpus_dir: str | None = None
    # a path to the dictionay file
    fuzzdict: str | None = None
    # combination length, tuple of minimal and maximal length.
    comblen: tuple[int, int] = (5, 10)

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
