import json
import os
import re
import subprocess
import tempfile
import traceback

from agentfuzz.analyzer.static.ast import APIGadget, ASTParser, TypeGadget


class CStyleAPIGadget(APIGadget):
    def signature(self) -> str:
        """Render the api gadget into C/C++ style declaration.
        Returns:
            `return_type name(list of arguments)`
        """
        args = ", ".join(
            f"{type_} {name or ''}".strip() for name, type_ in self.arguments
        )
        return f"{self.return_type} {self.name}({args})"


class CStyleTypeGadget(TypeGadget):
    def signature(self) -> str:
        """Render the type gadget into C/C++ style declaration."""
        match self.tag:
            case "alias":
                # using clause
                if self._meta["node"]["kind"] == "TypeAliasDecl":
                    return f"using {self.name} = {self.qualified};"
                else:
                    # typedef clause
                    # assert self._meta["node"]["kind"] == "TypedefDecl"
                    return f"typedef {self.qualified} {self.name};"
            case "class":
                return f"class {self.name};"
            case "struct":
                return f"struct {self.name};"


class ClangASTParser(ASTParser):
    """Clang AST-based static analysis supports."""

    def __init__(
        self, clang: int = "clang++", include_dir: list[str] = [], _max_cache: int = 500
    ):
        """Preare the clang ast parser.
        Args:
            clang: a path to the clang compiler.
            include_dir: a list of paths to the directories for `#incldue` preprocessor.
        """
        self.clang = clang
        self.include_dir = include_dir
        # for dumping cache
        self._ast_caches = {}
        self._cfg_caches = {}
        self._max_cache = _max_cache

    def parse_type_gadget(self, source: str) -> CStyleTypeGadget:
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
            if node.get("kind") not in [
                "TypeAliasDecl",
                "TypedefDecl",
                "CXXRecordDecl",
            ]:
                stack.extend(node.get("inner", []))
                continue
            # retrieve the file path (by #include macro)
            loc = node.get("loc", {})
            file = loc.get("file") or loc.get("includedFrom", {}).get("file")
            if file is not None and file != source:
                continue

            gadget = CStyleTypeGadget(
                name=node.get("name"),
                tag=node.get("tagUsed", "alias"),
                qualified=node.get("type", {}).get("qualType", None),
                _meta={"node": node},
            )
            gadgets.append(gadget)
            # C++ allows nested type declaration
            if "inner" in node:
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

    def parse_api_gadget(self, source: str) -> CStyleAPIGadget:
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
            if node.get("kind") not in ["FunctionDecl"]:
                stack.extend(node.get("inner", []))
                continue
            # retrieve the file path (by #include macro)
            loc = node.get("loc", {})
            file = loc.get("file") or loc.get("includedFrom", {}).get("file")
            if file is not None and file != source:
                continue
            # function decl found
            type_ = node["type"]["qualType"]
            # parse type
            _, (_, args_i), *_ = self._parse_parenthesis(type_)
            ((return_t, args_t),) = re.findall(
                r"^(.+?)\s*\((.*?)\)$", type_[: args_i + 1]
            )
            _post_qualifier = type_[args_i + 1 :]
            # TODO: Mark as template parameter if `TemplateTypeParmDecl` taken
            arguments = [
                (subnode.get("name", None), subnode["type"]["qualType"])
                for subnode in node.get("inner", [])
                if subnode["kind"] == "ParmVarDecl"
            ]
            # for support variable argument
            if args_t.endswith("..."):
                arguments.append((None, "..."))
            # sanity check
            assert args_t == ", ".join(t for _, t in arguments)
            gadget = CStyleAPIGadget(
                name=node["name"],
                return_type=return_t,
                arguments=arguments,
                _meta={"_post_qualifier": _post_qualifier, "node": node},
            )
            gadgets.append(gadget)
        return gadgets

    def extract_critical_path(self, source: str) -> list[CStyleAPIGadget]:
        """Extract the critical path from the source code.
        Args:
            source: a path to the source code file.
        Returns:
            a list of longest API gadgets possible to call by seed corpus.
        """
        cfg = self._extract_cfg(source)
        nodes = {obj["_gvid"]: obj["label"] for obj in cfg["objects"]}

    def _parse_parenthesis(self, item: str) -> list[tuple[int, int]]:
        """Parse the parenthesis from the item for argument parser.
        Args:
            item: given string.
        Returns:
            list of tuples about start and end index of the inner parenthesis.
        """
        parsed, stack, idx = [], [0], 0
        while idx < len(item):
            s = item[idx:].find("(")
            e = item[idx:].find(")")
            if s == -1 and e == -1:
                break
            if e == -1 or (s >= 0 and s < e):
                idx += s + 1
                stack.append(idx)
                continue
            else:
                idx += e + 1
                parsed.append((stack.pop(), idx - 1))
                continue

        if len(stack) > 1:
            raise ValueError("unpaired parenthesis")
        if len(stack) > 0:
            parsed.append((stack.pop(), len(item)))
        return sorted(parsed, key=lambda x: x[0])

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
        dumped = self._run_ast_dump(source, self.clang, self.include_dir)
        if len(self._ast_caches) > self._max_cache:
            # FIFO
            self._ast_caches = dict(list(self._ast_caches.items())[1:])
        # update
        self._ast_caches[_key] = dumped
        return dumped

    def _extract_cfg(self, source: str):
        """Extract a control flow grpah from the given source code.
        Args:
            source: a path to the target source file.
        Returns:
            extracted control-flow graph.
        """
        with open(source) as f:
            code = f.read()
        _key = (source, code)
        if _key in self._cfg_caches:
            return self._cfg_caches[_key]
        # extract cfg
        extracted = self._run_cfg_dump(source, self.clang)
        if len(self._cfg_caches) > self._max_cache:
            # FIFO
            self._cfg_caches = dict(list(self._cfg_caches.items())[1:])
        # update
        self._cfg_caches[_key] = extracted
        return extracted

    @classmethod
    def _run_ast_dump(
        cls, source: str, clang: str = "clang++", include_dir: list[str] = []
    ):
        """Run the clang with ast-dump options.
        Args:
            source: a path to the target source file.
            clang: a path to the clang compiler.
            include_dir: a list of paths to the directories for `#include` preprocessor.
        Returns:
            dumped abstract syntax tree.
        """
        _include = [cmdarg for path in include_dir for cmdarg in ("-I", path)]

        proc = subprocess.run(
            [
                clang,
                "-fsyntax-only",
                "-Xclang",
                "-ast-dump=json",
                *_include,
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

    @classmethod
    def _run_cfg_dump(
        cls, source: str, clang: str = "clang++", target: list[str] | None = None
    ) -> list[dict]:
        """Run the clang for dump a control-flow graph.
        Args:
            source: a path to the target source file.
            clang: a path to the clang compiler.
        Returns:
            dumped control flow graph.
        """
        # temporal paths
        _temp = tempfile.mkdtemp()
        ir = os.path.join(_temp, "ir.ll")
        try:
            # transform C/C++ source to LLVM IR
            subprocess.run(
                [clang, "-S", "-emit-llvm", source, "-o", ir],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # extract the control-flow graph from the IR
            subprocess.run(
                ["opt", ir, "-p", "dot-cfg"],
                cwd=_temp,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if target is None:
                target = [
                    os.path.join(_temp, filename)
                    for filename in os.listdir(_temp)
                    if filename.startswith(".") and filename.endswith(".dot")
                ]
            # serialize it into a json
            for path in target:
                subprocess.run(
                    ["dot", "-Txdot_json", path, "-o", f"{path}.json"],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except subprocess.CalledProcessError as e:
            return {"error": e, "_traceback": traceback.format_exc()}
        # load json
        cfgs = {}
        for path in target:
            with open(f"{path}.json") as f:
                loaded = json.load(f)
            cfgs[os.path.basename(path)[1 : -len(".dot.json")]] = loaded

        return cfgs
