from dataclasses import dataclass, field


@dataclass
class Coverage:
    # list of coverages, {FUNCTION_NAME: {BRANCH_ID: #HIT}}
    functions: dict[str, dict[str, int]] = field(default_factory=dict)

    def cover(self, fn: str) -> float | None:
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
    def branch_coverage(self) -> float:
        """Compute the branch coverage."""
        return len(self.flat(nonzero=True)) / len(self.flat(nonzero=False))

    def merge(self, other: "Coverage"):
        """Merge with the other one.
        Args:
            other: another coverage.
        """
        self.functions = {
            fn: {
                id_: self.functions.get(fn, {}).get(id_, 0)
                + other.functions.get(fn, {}).get(id_, 0)
                for id_ in set(self.functions.get(fn, {}))
                | set(other.functions.get(fn, {}))
            }
            for fn in set(self.functions) | set(other.functions)
        }
