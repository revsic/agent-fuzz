from agentfuzz.analyzer.dynamic.coverage import Coverage


class Fuzzer:
    """Executable fuzzer object."""

    def run(
        self,
        corpus_dir: str | None = None,
        fuzzdict: str | None = None,
        wait_until_done: bool = False,
        timeout: float = 300,
    ) -> int | Exception | None:
        """Run the compiled harness with given corpus directory and the fuzzer dictionary.
        Args:
            corpus_dir: a path to the directory containing fuzzing inputs (corpus).
            fuzzdict: a path to the fuzzing dictionary file.
            wait_until_done: wait for the fuzzer done if it is True.
            timeout: fuzzer timeout.
        Returns:
            int: return code of the fuzzer process.
            None: if fuzzer process is now running.
            Exception: if the fuzzer process does not exist or timeout occured.
        """
        raise NotImplementedError("Fuzzer.run is not implemented.")

    def poll(self) -> int | Exception | None:
        """Poll the return code of the fuzzer process and clear if process done.
        Returns:
            int: return code of the fuzzer process.
            None: if fuzzer process is running now.
            Exception: if the fuzzer process deos not exist or timeout occured.
        """
        raise NotImplementedError("Fuzzer.poll is not implemented.")

    def coverage(self) -> Coverage:
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
