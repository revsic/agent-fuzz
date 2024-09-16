import json
from dataclasses import dataclass

import yaml


@dataclass
class Config:
    name: str
    srcdir: str
    postfix: str

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
