import types
from dataclasses import dataclass, asdict


@dataclass
class APIGadget:
    name: str
    return_type: str
    arguments: list[tuple[str | None, str]]
    _meta: dict
    _dumped_signature: str | None = None

    def signature(self) -> str:
        """Render the gadget into a single declaration."""
        raise NotImplementedError("APIGadget.signature is not implemented.")

    def dump(self) -> dict:
        """Dump the gadget into the json-serializable object."""
        dumped = asdict(self)
        dumped["_dumped_signature"] = self.signature()
        return dumped

    @classmethod
    def load(cls, dumped: dict) -> "APIGadget":
        """Load the dumped object."""
        loaded = cls(**dumped)
        # backup the signature
        sign = loaded.signature

        def _hook_signature(self: APIGadget) -> str:
            if self._dumped_signature is not None:
                return self._dumped_signature
            return sign()

        # hook
        loaded.signature = types.MethodType(_hook_signature, loaded)
        return loaded


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

    def extract_critical_path(
        self, source: str, gadgets: list[APIGadget]
    ) -> list[list[tuple[str | APIGadget, int | None]]]:
        """Extract the ciritical path from the source code.
        Args:
            source: a path to the source code file.
            gadgets: a list of interests, return only the apis involved in `gadgets` if provided.
                returns the function name instead of gadgets if it is not provided.
        Returns:
            a list of longest API gadget sequences and their line numbers.
        """
        raise NotImplementedError("ASTParser.extract_critical_path is not implemented")

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
