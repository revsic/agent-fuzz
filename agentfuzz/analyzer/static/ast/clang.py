import json
import subprocess

from agentfuzz.analyzer.static.ast.base import APIGadget, ASTParser


class ClangASTParser(ASTParser):
    """Clang AST-based static analysis supports."""

    def __init__(self, include_path: str | list[str] | None = None):
        """Preare the clang ast parser.
        Args:
            include_path: paths to the directories for `#incldue` preprocessor.
        """
        self.include_path = include_path

    def parse_api_gadget(self, source: str) -> APIGadget:
        """Parse the API infos from the header file.
        Args:
            source: a path to the source code file.
        Returns:
            list of API gadgets.
        """
        pass

    @staticmethod
    def _run_ast_dump(source: str, include_path: str | list[str] | None = None):
        """Run the clang with ast-dump options.
        Args:
            source: a path to the target source file.
            include_path: paths to the directories for `#include` preprocessor.
        Returns:
            dumped abstract syntax tree.
        """
        _include = []
        if include_path is not None:
            if isinstance(include_path, str):
                include_path = [include_path]
            _include = [cmdarg for path in include_path for cmdarg in ("-I", path)]

        proc = subprocess.run(
            [
                "clang++",
                "-fsyntax-only",
                "-Xclang",
                "-ast-dump=json",
            ]
            + _include
            + [
                source,
            ],
            capture_output=True,
        )
        ast = proc.stdout.decode("utf-8")
        return json.loads(ast)
