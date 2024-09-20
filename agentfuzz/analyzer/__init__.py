import os

from agentfuzz.analyzer.static import APIGadget, ASTParser, GNUGlobal, TypeGadget
from agentfuzz.analyzer.dynamic import Compiler, Fuzzer
from agentfuzz.config import Config


class Factory:
    """Analyze the project and retrieve the knowledges."""

    def __init__(
        self,
        workdir: str,
        config: Config,
        parser: ASTParser,
        compiler: Compiler,
    ):
        """Initialize the harness generator.
        Args:
            workdir: a path to the workspace directory for writing some logs and intermediate results.
            config: the configurations of the harness generation pipeline.
            parser: an abstract syntax tree parser.
            compiler: a compiler for generating an executable object from a harness code.
        """
        self.workdir = workdir
        self.config = config
        self.parser = parser
        self.compiler = compiler
        self.tags = GNUGlobal.gtags(
            self.config.srcdir, tagdir=os.path.join(self.workdir, "tags")
        )

    def listup_files(self) -> list[str]:
        """Listup the files which containing the API Gadgets.
        Maybe header files of the C/C++ project, all python files of the python project, etc.

        Returns:
            list of paths to the source files.
        """
        return [
            os.path.join(root, filename)
            for root, _, files in os.walk(self.config.srcdir)
            for filename in files
            if filename.endswith(self.config.postfix)
        ]

    def listup_apis(self) -> list[APIGadget]:
        """Listup the API gadgets.
        Returns:
            list of api gadgets from the projects, which will be targeted by generated harness.
        """
        return [
            self.astparser.parse_api_gadget(source) for source in self.listup_files()
        ]

    def listup_types(self) -> list[TypeGadget]:
        """Listup the type gadgets.
        Returns:
            list of type gadgets from the projects.
        """
        return [
            self.astparser.parse_type_gadget(source) for source in self.listup_types()
        ]
