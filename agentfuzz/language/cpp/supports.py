import os
from dataclasses import dataclass, field

from agentfuzz.analyzer import Factory
from agentfuzz.config import Config
from agentfuzz.language.cpp.ast import ClangASTParser
from agentfuzz.language.cpp.compiler import Clang, _CXXFLAGS
from agentfuzz.language.supports import LanguageSupports


@dataclass
class CppConfig(Config):
    """Configurations for C/C++ project."""

    # postfix for retrieve the source files form the source code directory.
    postfix: str | tuple | None = field(default_factory=lambda: (".h", ".hpp", ".hxx"))
    # file extension for the generated harness.
    ext: str = "cpp"
    # a path to the target library or binary, should be not none
    libpath: str = None
    # additional libraries for link
    links: list[str] = field(default_factory=list)
    # a path to the directory for preprocessing `#include` macro.
    include_dir: list[str] = field(default_factory=list)
    # a path to the clang compiler.
    clang: str = "clang++"
    # additional compiler arguments.
    flags: list[str] = field(default_factory=lambda: [*_CXXFLAGS])

    def __post_init__(self):
        assert self.libpath is not None, "libpath should be provided"


class CppFactory(Factory):
    """Override for listup only the valid header files"""

    def listup_files(self) -> list[str]:
        """Retrieve the files only from the include directory.
        Returns:
            a list of the header files.
        """
        include_dir = self.config.include_dir or [self.config.srcdir]
        return [
            os.path.join(root, filename)
            for dir_ in include_dir
            for root, _, files in os.walk(dir_)
            for filename in files
            if filename.endswith(tuple(self.config.postfix))
        ]


class CppSupports(LanguageSupports):
    """Harness generation project for C/C++."""

    _Config = CppConfig
    _Factory = CppFactory

    def __init__(self, workdir: str, config: CppConfig):
        """Initialize the C/C++ project.
        Args:
            workdir: a path to the workspace directory.
            config: a C/C++ project configurations.
        """
        super().__init__(
            workdir=workdir,
            config=config,
            factory=self._Factory(
                workdir,
                config,
                ClangASTParser(clang=config.clang, include_dir=config.include_dir),
                Clang(
                    libpath=config.libpath,
                    links=config.links,
                    include_dir=config.include_dir,
                    clang=config.clang,
                    flags=config.flags,
                ),
            ),
        )

    @classmethod
    def from_yaml(cls, projdir: str, config: str) -> LanguageSupports:
        """Construct project with the predefined configuration file.
        Args:
            projdir: a path to the project directory.
            config: a path to the configuration file, yaml format.
        """
        return cls(projdir, cls._Config.load_from_yaml(config))
