from dataclasses import dataclass

from agentfuzz.analyzer import Factory
from agentfuzz.config import Config
from agentfuzz.harness import HarnessGenerator
from agentfuzz.language.cpp.ast import ClangASTParser


@dataclass
class CppConfig(Config):
    """Configurations for C/C++ project."""

    # a path to the library
    libpath: str | None = None
    # a path to the directory for preprocessing `#include` macro.
    include_dir: str | list[str] | None = None


class CppProject:
    """Harness generation project for C/C++."""

    def __init__(self, workdir: str, config: CppConfig):
        """Initialize the C/C++ project.
        Args:
            workdir: a path to the workspace directory.
            config: a C/C++ project configurations.
        """
        self.factory = Factory(
            workdir, config, ClangASTParser(include_path=config.include_dir)
        )

    def run(self):
        """Run the AgentFuzz pipeline."""
        HarnessGenerator(self.factory).run()

    @classmethod
    def from_yaml(cls, projdir: str, config: str):
        """Construct project with the predefined configuration file.
        Args:
            projdir: a path to the project directory.
            config: a path to the configuration file, yaml format.
        """
        return cls(projdir, CppConfig.load_from_yaml(config))

    @classmethod
    def template(
        cls,
        workdir: str,
        srcdir: str,
        libpath: str | None = None,
        include_dir: str | list[str] | None = None,
        corpus_dir: str | None = None,
        fuzzdict: str | None = None,
    ):
        """Project template.
        Args:
            workdir: a path to the workspace directory.
            srcdir: a path to the source code directory.
        """
        config = CppConfig(
            workdir,
            srcdir=srcdir,
            postfix=(".h", ".hpp", ".hxx"),
            libpath=libpath,
            corpus_dir=corpus_dir,
            include_dir=include_dir or srcdir,
            fuzzdict=fuzzdict,
        )
        return cls(workdir, config)
