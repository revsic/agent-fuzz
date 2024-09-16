from dataclasses import dataclass

from agentfuzz.config import Config
from agentfuzz.language.cpp.ast import ClangASTParser
from agentfuzz.project import Project


@dataclass
class CppConfig(Config):
    """Configurations for C/C++ project."""

    # a path to the directory for preprocessing `#include` macro.
    include_dir: str | list[str] | None = None


class CppProject(Project):
    """Project information for C/C++."""

    def __init__(self, projdir: str, config: CppConfig):
        """Initialize the C/C++ project.
        Args:
            projdir: a path to the project directory.
            config: a C/C++ project configurations.
        """
        super().__init__(
            projdir, config, ClangASTParser(include_path=config.include_dir)
        )
