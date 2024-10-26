import json
import os
import re
import subprocess
import tempfile
import traceback
from typing import Callable

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
        gadgets, stack = {}, [*top_node["inner"]]
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
            if "name" not in node:
                continue

            gadget = CStyleTypeGadget(
                name=node.get("name"),
                tag=node.get("tagUsed", "alias"),
                qualified=node.get("type", {}).get("qualType", None),
                _meta={"node": node},
            )
            if gadget.signature() not in gadgets:
                gadgets[gadget.signature()] = gadget
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
                            and inner.get("name") == node["name"]
                        )
                    ]
                )
        return list(gadgets.values())

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
        gadgets, stack = {}, [*top_node["inner"]]
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
            if gadget.signature() not in gadgets:
                gadgets[gadget.signature()] = gadget
        return list(gadgets.values())

    def extract_critical_path(
        self,
        source: str,
        gadgets: list[CStyleAPIGadget] | None = None,
        target: str = "LLVMFuzzerTestOneInput",
    ) -> list[list[tuple[str | CStyleAPIGadget, int | None]]]:
        """Extract the critical path from the source code.
        Args:
            source: a path to the source code file.
            target: the specific function name to inspect.
            gadgets: the list of intersts, return only the apis involved in `gadgets` if provided.
        Returns:
            a list of longest API gadget sequences and their line numbers.
        """
        # extract the control flow graph
        extracted = self._extract_cfg(source, target=target)
        meta = extracted.pop("__meta__", {})
        (cfg,) = extracted.values()
        # placeholder
        gadget = None
        # construct the graph
        _call_stmt = re.compile(r"^(%\d+\s*=\s*)*call.+?@(.+?)\(.+$")
        nodes = {
            obj["_gvid"]: {
                "body": [
                    (gadget or found, lineno)
                    # parse the IRs
                    for ir, lineno in self._parse_dot_body(obj["label"], meta=meta)
                    for _, found in _call_stmt.findall(ir)
                    # name matching for C/C++ (exact or mangled)
                    if gadgets is None
                    or (gadget := self._find_gadget(found, gadgets or []))
                ],
                "next": [],
            }
            for obj in cfg["objects"]
        }
        for edge in cfg.get("edges", []):
            nodes[edge["tail"]]["next"].append(edge["head"])
        # find the path of the maximum length
        stack = [([0], nodes[0]["body"])]
        maxlen, maxapis = 0, []
        while stack:
            path, apis = stack.pop()
            *_, last = path
            # if end-of-code
            if not nodes[last]["next"]:
                # max length check
                if len(apis) > maxlen:
                    maxapis, maxlen = [apis], len(apis)
                elif len(apis) == maxlen:
                    maxapis.append(apis)
                continue
            # append without cycle
            stack.extend(
                [
                    (path + [i], apis + nodes[i]["body"])
                    for i in nodes[last]["next"]
                    if i not in path
                ]
            )
        # minimize
        minimized = []
        for apis in maxapis:
            if apis not in minimized:
                minimized.append(apis)
        return minimized

    def _parse_dot_body(
        self, body: str, meta: dict | None = None
    ) -> list[tuple[str, int | None]] | None:
        """Parse the graphviz json-format dot-file into a list of LLVM IRs.
        Args:
            body: the given `label` from the json-format dot-file.
            meta: a metadata for retrieving line numbers.
        Returns:
            a list of the LLVM IRs and their line numbers.
        """
        inner = re.findall(r"^\{(.+?)\}$", body)
        if not inner:
            return None
        (body,) = inner
        _debugs, _sources = meta.get("debugs", {}), meta.get("source", "").split("\n")
        # start to parse
        result = []
        for ir in body.strip("\\l").split("\\l"):
            if ir.startswith("|"):
                ir = ir[1:]
            # find to find the originals
            try:
                ir = next(i for i in _sources if i.startswith(ir))
            except:
                pass
            if not (dbgs := re.findall(r"!dbg !(\d+)", ir)):
                result.append((ir.strip(), None))
                continue
            # parsed debug information
            (dbg,) = dbgs
            if not (linenos := re.findall(r"line: (\d+)", _debugs.get(int(dbg), ""))):
                result.append((ir.strip(), None))
                continue
            (lineno,) = linenos
            result.append((ir.strip(), int(lineno)))
        return result

    def _find_gadget(
        self,
        name: str,
        gadgets: list[CStyleAPIGadget] | dict[str, CStyleAPIGadget],
        mangled: Callable[[str], re.Pattern] = lambda i: re.compile(f"^_Z.*\\d+{i}"),
    ) -> CStyleAPIGadget | None:
        """Find the gadget w.r.t. the given name.
        Args:
            name: the name of the target API.
            gadgets: a list of candidate gadgets.
            mangled: the rule for find the gadget from the mangled API name.
        Returns:
            the found gadgets or None.
        """
        if isinstance(gadgets, list):
            gadgets = {g.name: g for g in gadgets}
        if name in gadgets:
            return gadgets[name]
        # if name is mangled
        for gadget in gadgets.values():
            if mangled(gadget.name).findall(name):
                return gadget
        return None

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

    def _extract_cfg(
        self, source: str, target: str | None = "LLVMFuzzerTestOneInput"
    ) -> dict[str, dict]:
        """Extract a control flow grpah from the given source code.
        Args:
            source: a path to the target source file.
            target: specify a function target of CFG or extract from all functions.
        Returns:
            extracted control-flow graph.
        """
        with open(source) as f:
            code = f.read()
        _key = (source, code, target)
        if _key in self._cfg_caches:
            return self._cfg_caches[_key]
        # extract cfg
        extracted = self._run_cfg_dump(source, self.include_dir, self.clang, target)
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
        cls,
        source: str,
        include_dir: list[str] = [],
        clang: str = "clang++",
        target: str | None = None,
    ) -> dict[str, dict]:
        """Run the clang for dump a control-flow graph.
        Args:
            source: a path to the target source file.
            include_dir: a list of paths to the directories for `#include` preprocessor.
            clang: a path to the clang compiler.
            target: specify a function target or generate all.
        Returns:
            dumped control flow graph.
        """
        # temporal paths
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as _temp:
            ir = os.path.join(_temp, "ir.ll")
            log = os.path.join(_temp, "log")
            try:
                with open(log, "w") as f:
                    _include = [
                        cmdarg for path in include_dir for cmdarg in ("-I", path)
                    ]
                    # transform C/C++ source to LLVM IR
                    _cmd = [
                        clang,
                        "-S",
                        "-g",
                        "-O0",
                        "-Xclang",
                        "-disable-O0-optnone",
                        "-emit-llvm",
                        source,
                        "-o",
                        ir,
                        *_include,
                    ]
                    subprocess.run(
                        _cmd, check=True, stdout=f, stderr=f, close_fds=False
                    )
                    # extract the control-flow graph from the IR
                    try:
                        # Mac OS LLVM Supports (tested on LLVM 18.1.8, arm64-apple-darwin23.5.0)
                        _cmd = ["opt", ir, "-p", "dot-cfg"]
                        if target:
                            _cmd.append(f"-cfg-func-name={target}")
                        subprocess.run(
                            _cmd,
                            cwd=_temp,
                            check=True,
                            stdout=f,
                            stderr=f,
                            close_fds=False,
                        )
                    except subprocess.CalledProcessError:
                        # Ubuntu LLVM Supports (tested on 15.0.7, x86_64-pc-linux-gnu)
                        _cmd = ["opt", ir, "--dot-cfg"]
                        if target:
                            _cmd.append(f"-cfg-func-name={target}")
                        subprocess.run(
                            _cmd,
                            cwd=_temp,
                            check=True,
                            stdout=f,
                            stderr=f,
                            close_fds=False,
                        )

                    files = [
                        os.path.join(_temp, filename)
                        for filename in os.listdir(_temp)
                        if filename.startswith(".") and filename.endswith(".dot")
                    ]
                    # serialize it into a json
                    for path in files:
                        subprocess.run(
                            ["dot", "-Txdot_json", path, "-o", f"{path}.json"],
                            check=True,
                            stdout=f,
                            stderr=f,
                            close_fds=False,
                        )
            except subprocess.CalledProcessError as e:
                with open(log) as f:
                    return {
                        "error": e,
                        "_traceback": traceback.format_exc(),
                        "_log": f.read(),
                    }
            # load json
            cfgs = {}
            for path in files:
                with open(f"{path}.json") as f:
                    loaded = json.load(f)
                cfgs[os.path.basename(path)[1 : -len(".dot.json")]] = loaded
            # metadata
            with open(ir) as f:
                ll = f.read()
                cfgs["__meta__"] = {
                    "source": ll,
                    "debugs": {
                        int(found[0]): line
                        for line in ll.split("\n")
                        if (found := re.findall(r"^!(\d+)", line))
                    },
                }

        return cfgs
