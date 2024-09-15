from dataclasses import dataclass


@dataclass
class APIGadget:
    pass


class ASTParser:
    """Abstract Syntax Tree-based Static analysis supports."""

    def parse_api_gadget(self, source: str) -> list[APIGadget]:
        """Parse the API infos from the source code.
        Args:
            source: a path to the source code file.
        Returns:
            list of API gadgets.
        """
        raise NotImplementedError("ASTParser.parse_api_gadget is not implemented")
