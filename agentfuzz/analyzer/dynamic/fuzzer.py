class Fuzzer:
    """Executable fuzzer object."""

    def run(self):
        """Run the fuzzer with compiled harness."""
        raise NotImplementedError("Fuzzer.run is not implemented.")

    def coverage(self):
        """Collect the branch coverage of the last fuzzer run."""
        raise NotImplementedError("Fuzzer.coverage is not implemented.")


class Compiler:
    """Compiler to make the harness executable."""

    def compile(self, srcfile: str) -> Fuzzer:
        """Compile the given harness to fuzzer object.
        Args:
            srcfile: a path to the source code file.
        Returns:
            fuzzer object.
        """
        raise NotImplementedError("Compiler.compile is not implemeneted.")
