import collections

from tqdm.auto import tqdm


def parse_lcov(lcov: str) -> dict[str, dict]:
    """Parse the lcov data.
    Args:
        lcov: file content of the lcov-format profiling coverage.
    Returns:
        structured data about the coverage about the lines, branches, functions and files.
    """
    # split into file-level units
    files = [
        file.strip().split("\n")
        for file in lcov.strip().split("end_of_record")
        if len(file.strip()) > 0
    ]
    assert all(file.startswith("SF:") for file, *_ in files)

    results = {}
    for file, *contents in tqdm(files):
        filename = file[len("SF:") :]
        # template
        parsed = {
            "__meta__": {
                "functions": {"found": None, "hit": None},
                "lines": {"found": None, "hit": None},
                "branches": {"found": None, "hit": None},
            },
            "functions": collections.defaultdict(dict),
            "lines": {},
            "branches": collections.defaultdict(dict),
        }
        results[filename] = parsed
        # parse the lcov-format contents
        for item in contents:
            type_, *args = item.strip().split(":")
            args = ":".join(args)
            match type_:
                case "FN":
                    lineno, filename = args.split(",")
                    parsed["functions"][filename]["lineno"] = int(lineno)
                case "FNDA":
                    execution, filename = args.split(",")
                    parsed["functions"][filename]["execution"] = int(execution)
                case "FNF":
                    parsed["__meta__"]["functions"]["found"] = int(args)
                case "FNH":
                    parsed["__meta__"]["functions"]["hit"] = int(args)
                case "DA":
                    lineno, execution, *_ = args.split(",")
                    assert len(_) <= 1, f"unknown item, {item}"
                    parsed["lines"][int(lineno)] = int(execution)
                case "BRDA":
                    lineno, blockno, branchno, taken = args.split(",")
                    parsed["branches"][int(lineno)][(int(blockno), int(branchno))] = (
                        None if taken == "-" else int(taken)
                    )
                case "LF":
                    parsed["__meta__"]["lines"]["found"] = int(args)
                case "LH":
                    parsed["__meta__"]["lines"]["hit"] = int(args)
                case "BRF":
                    parsed["__meta__"]["branches"]["found"] = int(args)
                case "BRH":
                    parsed["__meta__"]["branches"]["hit"] = int(args)
                case _:
                    assert False, f"unknown item, {item}"
        # sort with line number
        functions = sorted(
            parsed.pop("functions").items(), key=lambda x: x[1]["lineno"]
        )

        # find the function name within the line number
        def _find(lineno: int) -> str | None:
            try:
                return next(
                    k
                    for (k, start), (_, end) in zip(
                        functions, functions[1:] + [(None, None)]
                    )
                    if start["lineno"] <= lineno
                    and (end is None or lineno < end["lineno"])
                )
            except StopIteration:
                return None

        # reorder within the function-unit
        branches = collections.defaultdict(dict)
        for lineno, _branches in parsed["branches"].items():
            branches[_find(lineno)][lineno] = _branches

        lines = collections.defaultdict(dict)
        for lineno, execution in parsed["lines"].items():
            lines[_find(lineno)][lineno] = execution
        # reassign
        parsed["functions"] = {
            function: {
                "branches": branches.get(function, {}),
                "lines": lines.get(function, {}),
                "execution": v["execution"],
                "lineno": v["lineno"],
            }
            for function, v in functions
        }

    return results
