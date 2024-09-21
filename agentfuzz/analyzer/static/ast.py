from dataclasses import dataclass


@dataclass
class APIGadget:
    name: str
    return_type: str
    arguments: list[tuple[str | None, str]]
    _meta: dict

    def signature(self) -> str:
        """Render the gadget into a single declaration."""
        raise NotImplementedError("APIGadget.signature is not implemented.")


@dataclass
class TypeGadget:
    name: str
    tag: str
    qualified: str | None
    _meta: dict

    def signature(self) -> str:
        """Render the gadget into a single declaration."""
        raise NotImplementedError("TypeGadget.signature is not implemented.")


class ASTParser:
    """Abstract Syntax Tree-based Static analysis supports."""

    def parse_type_gadget(self, source: str) -> list[TypeGadget]:
        """Parse the declared type infos from the source code.
        Args:
            source: a path to the source code file.
        Returns:
            a list of type gadgets.
        """
        raise NotImplementedError("ASTParser.parse_type_gadget is not implemented")

    def parse_api_gadget(self, source: str) -> list[APIGadget]:
        """Parse the API infos from the source code.
        Args:
            source: a path to the source code file.
        Returns:
            a list of API gadgets.
        """
        raise NotImplementedError("ASTParser.parse_api_gadget is not implemented")

    def retrieve_type(
        self, api: APIGadget, types: list[TypeGadget]
    ) -> list[TypeGadget]:
        """Retrieve relevant type gadgets about the given api.
        Args:
            api: the target api gadget.
            types: a list of type gadget candidates.
        Returns:
            a list of relevant type gadgets.
        """
        return [
            gadget
            for gadget in types
            if api.return_type == gadget.name
            or any(arg_t == gadget.name for _, arg_t in api.arguments)
        ]
