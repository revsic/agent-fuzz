import os
import shutil
import subprocess
from time import time

from agentfuzz.analyzer import Compiler, Coverage, Fuzzer
from agentfuzz.language.cpp.lcov import parse_lcov


class LibFuzzer(Fuzzer):
    """Libfuzzer wrapper."""

    def __init__(
        self,
        path: str,
        libpath: str,
        minimize_corpus: bool = True,
        _workdir: str | None = None,
    ):
        """Initialize the fuzzer wrapper.
        Args:
            path: a path to the executable file.
            libpath: a path to the library for tracking the coverage.
            minimize_corpus: minimize the corpus if given is True, using a `-merge=1` option.
            _workdir: a path to the working directory, use `{os.path.dirname(path)}` if it is not provided.
        """
        self.path = path
        self.libpath = libpath
        self.minimize_corpus = minimize_corpus
        self._workdir = _workdir or os.path.dirname(self.path)
        # for supporting parallel run
        self._proc: subprocess.Popen | None = None
        self._timeout: float | None = None

    def _minimize_corpus(
        self, corpus_dir: str, outdir: str | None = None
    ) -> str | None:
        """Minimize the corpus with a `-merge=1` option.
        Args:
            corpus_dir: a path to the directory containing fuzzing inputs (corpus).
            outdir: a path to the directory to write a minimized corpus.
                assume it as `os.path.join(self._workdir, f"{os.path.basename(corpus_dir)}_min)"` if it is not provided.
        Returns:
            a path to the directory where minimized corpus is written.
                None if minimizing process is failed.
        """
        outdir = outdir or os.path.join(
            self._workdir, f"{os.path.basename(corpus_dir)}_min"
        )
        os.makedirs(outdir, exist_ok=True)
        with open(f"{self.path}.minimize.log", "wb") as f:
            run = subprocess.run([self.path, "-merge=1", outdir, corpus_dir], stderr=f)
        try:
            run.check_returncode()
        except subprocess.CalledProcessError:
            return None
        return outdir

    def run(
        self,
        corpus_dir: str | None = None,
        fuzzdict: str | None = None,
        wait_until_done: bool = False,
        timeout: float | None = 300.0,
        runs: int | None = None,
        _profile: str | None = None,
        _logfile: str | None = None,
    ) -> int | Exception | None:
        """Run the compiled harness with given corpus directory and the fuzzer dictionary.
        Args:
            corpus_dir: a path to the directory containing fuzzing inputs (corpus).
            fuzzdict: a path to the fuzzing dictionary file.
            wait_until_done: wait for the fuzzer done.
            timeout: the maximum running time in seconds.
            runs: the number of individual tests, None or -1 for indefinitely run.
            _profile: a path to the coverage profiling file, use `{self.path}.profraw` if it is not provided.
            _logfile: a path to the fuzzing log file, use `{self.path}.log` if it is not provided.
        Returns:
            int: return code of the fuzzer process.
            None: if fuzzer process is running now.
            Exception: if the fuzzer process deos not exist or timeout occured.
        """
        assert not wait_until_done or (
            timeout is not None or runs is not None
        ), "hang may occur"
        # if already run
        if self._proc is not None:
            return self.poll()
        # isolate the corpus directory
        if corpus_dir is not None:
            if self.minimize_corpus:
                # if successfully minimized
                if minimized := self._minimize_corpus(corpus_dir):
                    corpus_dir = minimized
            else:
                # since libfuzzer generate the new corpus inplace the directory
                _new_dir = os.path.join(self._workdir, "corpus")
                shutil.copytree(corpus_dir, _new_dir)
                corpus_dir = _new_dir
        # run the fuzzer
        cmd = [self.path]
        if corpus_dir is not None:
            cmd.append(corpus_dir)
        if fuzzdict is not None:
            cmd.append(f"-dict={fuzzdict}")
        if runs is not None:
            cmd.append(f"-runs={runs}")

        self._proc = subprocess.Popen(
            cmd,
            stderr=open(_logfile or f"{self.path}.log", "wb"),
            env={**os.environ, "LLVM_PROFILE_FILE": _profile or f"{self.path}.profraw"},
        )
        if timeout is not None:
            self._timeout = time() + timeout
        if not wait_until_done:
            return self.poll()
        # wait until done
        try:
            self._proc.wait(timeout)
        except subprocess.TimeoutExpired:
            pass
        # return code
        retn = self.poll()
        # hard clear (for preventing process miss-clear)
        self.clear()
        return retn

    def poll(self) -> int | None | Exception:
        """Poll the return code of the fuzzer process and clear if process done.
        Returns:
            int: return code of the fuzzer process.
            None: if fuzzer process is running now.
            Exception: if the fuzzer process deos not exist or timeout occured.
        """
        if self._proc is None:
            return RuntimeError("process is not running now")
        # if the process is running and before timeout
        if (retn := self._proc.poll()) is None and time() < self._timeout:
            return None
        # clear
        self.clear()
        # return code if exists. otherwise, return timeouterror
        return retn or TimeoutError(f"fuzzer process {self.path} timeout")

    def clear(self):
        """Clear the fuzzing process (kill the process if it is running)."""
        if self._proc is None:
            return
        if self._proc.poll() is None:
            self._proc.kill()
        if self._proc.stdout is not None:
            self._proc.stdout.close()
        self._proc, self._timeout = None, None

    def coverage(
        self, libpath: str | None = None, _profile: str | None = None
    ) -> Coverage:
        """Collect the coverage w.r.t. the given library.
        Args:
            libpath: a path to the target library, assume it as `self.libpath` if it is not provided.
            _profile: a path to the coverage profiling file, assume it as f"{self.path}.profraw" if it is not provded.
        """
        # assign default value
        _profile = _profile or f"{self.path}.profraw"
        _merged = _profile.replace(".profraw", ".profdata")
        # merge the raw profile
        try:
            run = subprocess.run(
                ["llvm-profdata", "merge", "-sparse", _profile, "-o", _merged]
            )
            run.check_returncode()
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"failed to merge the raw profile data `{_profile}` to `{_merged}`"
            ) from e
        # return the coverage
        cov: dict
        try:
            run = subprocess.run(
                [
                    "llvm-cov",
                    "export",
                    libpath or self.libpath,
                    "-format=lcov",
                    f"--instr-profile={_merged}",
                ],
                capture_output=True,
            )
            run.check_returncode()
            cov = parse_lcov(run.stdout.decode("utf-8"))
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"failed to extract the coverage from the profile data `{_merged}`"
            ) from e
        except Exception as e:
            raise RuntimeError(
                f"failed to parse the lcov-format coverate data from profile `{_merged}`"
            ) from e
        # pack to coverage
        packed = Coverage()
        for filelevel in cov.values():
            packed.merge(
                Coverage(
                    {
                        fn: {
                            f"L{lineno}#({blockno}, {branchno})": hit or 0
                            for lineno, branches in info["branches"].items()
                            for (blockno, branchno), hit in branches.items()
                        }
                        for fn, info in filelevel["functions"].items()
                    }
                )
            )
        return packed


_CXXFLAGS = [
    "-g",  # debug information
    "-fno-omit-frame-pointer",  # do not omit stack frame pointer
    "-fsanitize=address,undefined",  # asan, ubsan
    "-fsanitize-address-use-after-scope",
    "-fsanitize=fuzzer",
    "-fsanitize=fuzzer-no-link",  # libfuzzer supports
    "-fprofile-instr-generate",  # profile instrumentation supports
    "-fcoverage-mapping",  # coverage supports
]


class Clang(Compiler):
    """Compile the C/C++ project with clang w/libfuzzer."""

    def __init__(
        self,
        libpath: str,
        links: list[str] = [],
        include_dir: list[str] = [],
        clang: str = "clang++",
        flags: list[str] = _CXXFLAGS,
    ):
        """Prepare for the compile.
        Args:
            libpath: a path to the library path.
            links: additional libraries to link.
            include_dir: a list of paths to the directory for preprocessing #include macro.
            clang: a path to the clang compiler.
            flags: additional compiler arguments.
        """
        self.libpath = libpath
        self.links = links
        self.include_dir = include_dir
        self.clang = clang
        self.flags = flags

    def compile(
        self,
        srcfile: str,
        _workdir: str | None = None,
        _outpath: str | None = None,
    ) -> LibFuzzer:
        """Compile the given harness to fuzzer object.
        Args:
            srcfile: a path to the source code file.
            _workdir: a path to the working directory, use `{os.path.splitext(srcfile)[0]}` if it is not provided
            _outpath: a path to the compiled binary, use `{_workdir}/{os.path.basename(srcfile)}.out` if it is not provided.
        Returns:
            fuzzer object.
        """
        if _workdir is None:
            _workdir = os.path.dirname(srcfile)
        os.makedirs(_workdir, exist_ok=True)
        _include_args = [arg for path in self.include_dir for arg in ("-I", path)]
        executable = _outpath or f"{_workdir}/{os.path.basename(srcfile)}.out"
        output = subprocess.run(
            [
                self.clang,
                *self.flags,
                srcfile,
                *_include_args,
                "-o",  # specifying the output path
                executable,
                self.libpath,  # linkage
                *self.links,
            ],
            capture_output=True,
        )
        try:
            output.check_returncode()
        except subprocess.CalledProcessError as e:
            stderr = output.stderr.decode("utf-8")
            raise RuntimeError(
                f"{self.clang} returned non-zero exit status:\n{stderr}"
            ) from e

        return LibFuzzer(executable, self.libpath, _workdir=_workdir)
