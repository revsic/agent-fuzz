class Fuzzer:
    """Executable fuzzer object."""

    def run(
        self,
        corpus_dir: str | None = None,
        fuzzdict: str | None = None,
        timeout: float = 300,
    ):
        """Run the compiled harness with given corpus directory and the fuzzer dictionary.
        Args:
            corpus_dir: a path to the directory containing fuzzing inputs (corpus).
            fuzzdict: a path to the fuzzing dictionary file.
            timeout: fuzzer timeout.
        """
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
