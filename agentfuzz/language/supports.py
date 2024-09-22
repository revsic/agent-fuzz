from agentfuzz.analyzer import Factory
from agentfuzz.config import Config
from agentfuzz.harness.generator import HarnessGenerator


class LanguageSupports:
    """Agent-fuzz supports for a such language."""

    # Language specific configuration and factory
    _Config: type[Config] = Config
    _Factory: type[Factory] = Factory
    _Generator: type[HarnessGenerator] = HarnessGenerator

    def __init__(self, workdir: str, config: Config, factory: Factory):
        """Initialize the agent-fuzz projects for a target language.
        Args:
            workdir: a path to the working directory.
            config: configurations for the harness generation and fuzzing.
            factory: method factory.
        """
        self.workdir = workdir or factory.workdir
        self.config = config
        self.factory = factory

    def run(self):
        """Run the AgentFuzz pipeline."""
        self._Generator(self.factory, self.workdir).run()

    @classmethod
    def from_yaml(cls, workdir: str, config: str) -> "LanguageSupports":
        """Construct project with the predefined configuration file.
        Args:
            projdir: a path to the project directory.
            config: a path to the configuration file, yaml format.
        """
        raise NotImplementedError("LanguageSupports.from_yaml is not implemented.")