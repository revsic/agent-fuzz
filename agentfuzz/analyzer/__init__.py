import os

from agentfuzz.analyzer.static import APIGadget, ASTParser, GNUGlobal, TypeGadget
from agentfuzz.analyzer.dynamic import Compiler, Coverage, Fuzzer
from agentfuzz.config import Config


class Factory:
    """Analyze the project and retrieve the knowledges for LLM.

    The methods are all supposed to be the tools for a LLM function calling API.
    Consider that all the documentation will directly be fed to the LLM as a description of the tools.
    """

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
        """(Non-LLM API) Listup the files which containing the API Gadgets.
        Maybe header files from the C/C++ project, or all `.py` files from the python project.

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
        """(Non-LLM API) Listup the APIs.
        Returns:
            list of the APIs from the project, which will be used to generate harness.
        """
        apis = []
        for source in self.listup_files():
            try:
                apis.extend(self.parser.parse_api_gadget(source))
            except Exception as e:
                raise RuntimeError(
                    f"failed to parse the APIs from file `{source}`"
                ) from e
        return apis

    def listup_types(self) -> list[TypeGadget]:
        """(None-LLM API) Listup the user-defined types.
        Returns:
            list of types from the projects.
        """
        types = []
        for source in self.listup_files():
            try:
                types.extend(self.parser.parse_type_gadget(source))
            except Exception as e:
                raise RuntimeError(
                    f"failed to parse the types from file `{source}`"
                ) from e
        return types
