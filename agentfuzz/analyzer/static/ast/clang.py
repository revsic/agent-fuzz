import json
import os
import re
import subprocess
import traceback

from agentfuzz.analyzer.static.ast.base import APIGadget, ASTParser, TypeGadget


class ClangASTParser(ASTParser):
    """Clang AST-based static analysis supports."""

    def __init__(self, include_path: str | list[str] | None = None):
        """Preare the clang ast parser.
        Args:
            include_path: paths to the directories for `#incldue` preprocessor.
        """
        self.include_path = include_path
        # for dumping cache
        self._ast_caches = {}

    def parse_type_gadget(self, source: str) -> TypeGadget:
        """Parse the declared type infos from the header file.
        Args:
            source: a path to the source code file.
        Returns:
            list of type gadgets.
        """
        assert os.path.exists(source), f"FILE DOES NOT EXIST, {source}"
        # parse tree, cache supports
        top_node = self._parse_to_ast(source)
        assert "error" not in top_node, top_node
        # traversal
        gadgets, stack = [], [*top_node["inner"]]
        while stack:
            node = stack.pop()
            # TypeAliasDecl: using A = B;
            # TypedefDecl: typedef B A;
            # CXXRecordDecl: tagged by class, struct
            if node["kind"] not in ["TypeAliasDecl", "TypedefDecl", "CXXRecordDecl"]:
                stack.extend(node.get("inner", []))
                continue

            gadget = TypeGadget(
                name=node["name"],
                _meta={"node": node},
            )
            gadgets.append(gadget)
            # C++ allows nested type declaration
            stack.extend(
                [
                    inner
                    for inner in node["inner"]
                    # CXXRecordDecl contains self in the inner.
                    if not (
                        node["kind"] == "CXXRecordDecl"
                        and inner["kind"] == "CXXRecordDecl"
                        and inner["name"] == node["name"]
                    )
                ]
            )
        return gadgets

    def parse_api_gadget(self, source: str) -> APIGadget:
        """Parse the API infos from the header file.
        Args:
            source: a path to the source code file.
        Returns:
            list of API gadgets.
        """
        assert os.path.exists(source), f"FILE DOES NOT EXIST, {source}"
        # parse tree, cache supports
        top_node = self._parse_to_ast(source)
        assert "error" not in top_node, top_node
        # traversal
        gadgets, stack = [], [*top_node["inner"]]
        while stack:
            node = stack.pop()
            if node["kind"] not in ["FunctionDecl"]:
                stack.extend(node.get("inner", []))
                continue
            # function decl found
            type_ = node["type"]["qualType"]
            # parse type
            ((return_t, args_t),) = re.findall(r"^(.+?)\s*\((.*?)\)$", type_)
            # TODO: Mark as template parameter if `TemplateTypeParmDecl` taken
            arguments = [
                (subnode.get("name", None), subnode["type"]["qualType"])
                for subnode in node.get("inner", [])
                if subnode["kind"] == "ParmVarDecl"
            ]
            # sanity check
            assert args_t == ", ".join(t for _, t in arguments)
            gadget = APIGadget(
                name=node["name"],
                return_type=return_t,
                arguments=arguments,
                _meta={"node": node},
            )
            gadgets.append(gadget)
        return gadgets

    def _parse_to_ast(self, source: str):
        """Parse the source code to extract the abstract syntax tree.
        Args:
            source: a path to the target source file.
        Returns:
            parsed abstract syntax tree.
        """
        with open(source) as f:
            code = f.read()
        _key = (source, code)
        if _key in self._ast_caches:
            return self._ast_caches[_key]
        # dump the ast
        dumped = self._run_ast_dump(source, self.include_path)
        self._ast_caches[_key] = dumped
        return dumped

    @classmethod
    def _run_ast_dump(cls, source: str, include_path: str | list[str] | None = None):
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
        try:
            return json.loads(ast)
        except Exception as e:
            return {
                "error": e,
                "_traceback": traceback.format_exc(),
                "_stdout": ast,
            }
