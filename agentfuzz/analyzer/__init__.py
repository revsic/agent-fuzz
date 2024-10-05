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

    def listup_files(self) -> list[tuple[str, str]]:
        """(Non-LLM API) Listup the files which containing the API Gadgets.
        Maybe header files from the C/C++ project, or all `.py` files from the python project.

        Returns:
            list of paths to the source files.
        """
        return [
            (
                self.config.srcdir,
                os.path.relpath(os.path.join(root, filename), self.config.srcdir),
            )
            for root, _, files in os.walk(self.config.srcdir)
            for filename in files
            if filename.endswith(tuple(self.config.postfix))
        ]

    def listup_apis(self) -> list[APIGadget]:
        """(Non-LLM API) Listup the APIs.
        Returns:
            list of the APIs from the project, which will be used to generate harness.
        """
        apis = {}
        for mother, relpath in self.listup_files():
            full = os.path.join(mother, relpath)
            try:
                for gadget in self.parser.parse_api_gadget(full):
                    if gadget.signature() in apis:
                        continue
                    # WARNING: inplace operation
                    gadget._meta["__source__"] = relpath
                    apis[gadget.signature()] = gadget
            except Exception as e:
                raise RuntimeError(
                    f"failed to parse the APIs from file `{full}`"
                ) from e
        return list(apis.values())

    def listup_types(self) -> list[TypeGadget]:
        """(None-LLM API) Listup the user-defined types.
        Returns:
            list of types from the projects.
        """
        types = {}
        for mother, relpath in self.listup_files():
            full = os.path.join(mother, relpath)
            try:
                for gadget in self.parser.parse_type_gadget(full):
                    if gadget.signature() in types:
                        continue
                    # WARNING: inplace operation
                    gadget._meta["__source__"] = relpath
                    types[gadget.signature()] = gadget
            except Exception as e:
                raise RuntimeError(
                    f"failed to parse the types from file `{full}`"
                ) from e
        return list(types.values())
