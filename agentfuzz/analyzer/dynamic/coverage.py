from dataclasses import dataclass, field


@dataclass
class Coverage:
    # list of branch coverages, {FUNCTION_NAME: {BRANCH_ID: #HIT}}
    functions: dict[str, dict[str, int]] = field(default_factory=dict)
    # list of line coverages, {FILE_NAME: {str(LINENO): #HIT}}
    lines: dict[str, dict[str, int]] = field(default_factory=dict)

    def cover_branch(self, fn: str) -> float | None:
        """Return the branch coverage of the given function.
        Args:
            fn: the name of the given function.
        Returns:
            branch coverage.
        """
        if fn not in self.functions or len(self.functions[fn]) == 0:
            return None
        return sum(hit > 0 for hit in self.functions[fn].values()) / len(
            self.functions[fn]
        )

    def cover_lines(self, filename: str, lineno: int) -> bool | None:
        """Return the line coverage of the given file.
        Args:
            filename: target file path.
            lineno: the given line numbar.
        Returns:
            whether the given line is covered.
        """
        if filename not in self.lines:
            return None
        return self.lines[filename].get(str(lineno), 0) > 0

    def flat(self, nonzero: bool = False) -> dict[str, int]:
        """Flatten the functions into a dictionary of branches and their hits.
        Args:
            nonzero: whether return the nonzero branches or not.
        Returns:
            branches and their hits.
        """
        return {
            f"{fn=}/{branch=}": hit
            for fn, branches in self.functions.items()
            for branch, hit in branches
            if not nonzero or hit > 0
        }

    @property
    def coverage_branch(self) -> float:
        """Compute the branch coverage."""
        return len(self.flat(nonzero=True)) / max(len(self.flat(nonzero=False)), 1)

    def merge(self, other: "Coverage"):
        """Merge with the other one.
        Args:
            other: another coverage.
        """
        _merge = lambda a, b: {
            key: {
                id_: a.get(key, {}).get(id_, 0) + b.get(key, {}).get(id_, 0)
                for id_ in set(a.get(key, {})) | set(b.get(key, {}))
            }
            for key in set(a) | set(b)
        }
        self.functions = _merge(self.functions, other.functions)
        self.lines = _merge(self.lines, other.lines)
