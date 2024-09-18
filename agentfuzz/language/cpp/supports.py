from dataclasses import dataclass

from agentfuzz.config import Config
from agentfuzz.language.cpp.ast import ClangASTParser
from agentfuzz.project import Project


@dataclass
class CppConfig(Config):
    """Configurations for C/C++ project."""

    # a path to the library
    libpath: str
    # a path to the corpus directory
    corpus_dir: str
    # a path to the directory for preprocessing `#include` macro.
    include_dir: str | list[str] | None = None
    # a path to the dictionary file
    fuzzdict: str | None = None


class CppProject(Project):
    """Harness generation project for C/C++."""

    def __init__(self, projdir: str, config: CppConfig):
        """Initialize the C/C++ project.
        Args:
            projdir: a path to the project directory.
            config: a C/C++ project configurations.
        """
        super().__init__(
            projdir, config, ClangASTParser(include_path=config.include_dir)
        )

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
        projdir: str,
        srcdir: str,
        libpath: str,
        corpus_dir: str,
        include_dir: str | list[str] | None = None,
        fuzzdict: str | None = None,
    ):
        """Project template.
        Args:
            projdir: a path to the project directory.
            srcdir: a path to the source code directory.
            include_dir: a path to the directory for preprocessing `#include` macro.
        """
        config = CppConfig(
            projdir,
            srcdir=srcdir,
            postfix=(".h", ".hpp", ".hxx"),
            libpath=libpath,
            corpus_dir=corpus_dir,
            include_dir=include_dir or srcdir,
            fuzzdict=fuzzdict,
        )
        return cls(projdir, config)
