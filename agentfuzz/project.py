import os

from agentfuzz.config import Config
from agentfuzz.analyzer.static import APIGadget, ASTParser, GNUGlobal, TypeGadget


class Project:
    """Project information for harness generation."""

    def __init__(
        self,
        projdir: str,
        config: Config,
        astparser: ASTParser,
    ):
        """Initialize the project information.
        Args:
            projdir: a path to the project directory for writing some logs and intermediate results.
            config: the configurations of the harness generation pipeline.
            astparser: an abstract syntax tree parser.
        """
        self.projdir = projdir
        self.config = config
        self.astparser = astparser
        self.tags = GNUGlobal.gtags(
            self.config.srcdir, tagdir=os.path.join(self.projdir, "tags")
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
