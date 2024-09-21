from dataclasses import dataclass, field

from agentfuzz.analyzer import Factory
from agentfuzz.config import Config
from agentfuzz.harness import HarnessGenerator
from agentfuzz.language.cpp.ast import ClangASTParser
from agentfuzz.language.cpp.fuzzer import Clang, _CXXFLAGS


@dataclass
class CppConfig(Config):
    """Configurations for C/C++ project."""

    # postfix for retrieve the source files form the source code directory.
    postfix: str | tuple | None = field(default_factory=lambda: (".h", ".hpp", ".hxx"))
    # a path to the target library or binary, should be not none
    libpath: str = None
    # additional libraries for link
    links: list[str] = field(default_factory=list)
    # a path to the directory for preprocessing `#include` macro.
    include_dir: str | list[str] | None = None
    # a path to the clang++ compiler.
    cxx: str = "clang++"
    # additional compiler arguments.
    cxxflags: list[str] = field(default_factory=lambda: [*_CXXFLAGS])

    def __post_init__(self):
        assert self.libpath is not None, "libpath should be provided"


class CppProject:
    """Harness generation project for C/C++."""

    Config = CppConfig

    def __init__(self, workdir: str, config: CppConfig):
        """Initialize the C/C++ project.
        Args:
            workdir: a path to the workspace directory.
            config: a C/C++ project configurations.
        """
        self.factory = Factory(
            workdir,
            config,
            ClangASTParser(include_path=config.include_dir),
            Clang(
                libpath=[config.libpath] + config.links,
                include_dir=config.include_dir,
                cxx=config.cxx,
                cxxflags=config.cxxflags,
            ),
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
        return cls(projdir, cls.Config.load_from_yaml(config))
