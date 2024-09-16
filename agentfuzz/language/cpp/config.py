from dataclasses import dataclass

from agentfuzz.config import Config


@dataclass
class CppConfig(Config):
    include_dir: str | None = None
