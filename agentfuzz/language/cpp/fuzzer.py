import os
import subprocess
import tempfile
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
    ):
        """Initialize the fuzzer wrapper.
        Args:
            path: a path to the executable file.
            libpath: a path to the library for tracking the coverage.
            minimize_corpus: minimize the corpus if given is True, using a `-merge=1` option.
        """
        self.path = path
        self.libpath = libpath
        self.minimize_corpus = minimize_corpus
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
                assume it as `f"{corpus_dir}_min"` if it is not provided.
        Returns:
            a path to the directory where minimized corpus is written.
                None if minimizing process is failed.
        """
        outdir = outdir or f"{corpus_dir}_min"
        os.makedirs(outdir, exist_ok=True)
        run = subprocess.run([self.path, "-merge=1", outdir, corpus_dir])
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
        _profile: str | None = None,
        _logfile: str | None = None,
    ) -> int | Exception | None:
        """Run the compiled harness with given corpus directory and the fuzzer dictionary.
        Args:
            corpus_dir: a path to the directory containing fuzzing inputs (corpus).
            fuzzdict: a path to the fuzzing dictionary file.
            wait_until_done: wait for the fuzzer done.
            timeout: the maximum running time in seconds.
            _profile: a path to the coverage profiling file, use `{self.path}.profraw` if it is not provided.
            _logfile: a path to the fuzzing log file, use `{self.path}.log` if it is not provided.
        Returns:
            int: return code of the fuzzer process.
            None: if fuzzer process is running now.
            Exception: if the fuzzer process deos not exist or timeout occured.
        """
        # if already run
        if self._proc is not None:
            return self.poll()
        # minimize the corpus first
        if self.minimize_corpus and corpus_dir is not None:
            # if successfully minimized
            if minimized := self._minimize_corpus(corpus_dir):
                corpus_dir = minimized
        # run the fuzzer
        cmd = [self.path]
        if corpus_dir is not None:
            cmd.append(corpus_dir)
        if fuzzdict is not None:
            cmd.extend(["-dict", fuzzdict])

        self._proc = subprocess.Popen(
            cmd,
            stderr=subprocess.STDOUT,
            stdout=open(_logfile or f"{self.path}.log", "wb"),
            env={**os.environ, "LLVM_PROFILE_FILE": _profile or f"{self.path}.profraw"},
        )
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

        return Coverage(cov)


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
        cxx: str = "clang++",
        cxxflags: list[str] = _CXXFLAGS,
    ):
        """Prepare for the compile.
        Args:
            libpath: a path to the library path.
            links: additional libraries to link.
            include_dir: a list of paths to the directory for preprocessing #include macro.
            cxx: a path to the clang++ compiler.
            cxxflags: additional compiler arguments.
        """
        self.libpath = libpath
        self.links = links
        self.include_dir = include_dir
        self.cxx = cxx
        self.cxxflags = cxxflags

    def compile(self, srcfile: str, _outpath: str | None = None) -> LibFuzzer:
        """Compile the given harness to fuzzer object.
        Args:
            srcfile: a path to the source code file.
        Returns:
            fuzzer object.
        """
        _include_args = [arg for path in self.include_dir for arg in ("-I", path)]
        executable = _outpath or tempfile.mktemp()
        output = subprocess.run(
            [
                self.cxx,
                *self.cxxflags,
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
                f"{self.cxx} returned non-zero exit status:\n{stderr}"
            ) from e

        return LibFuzzer(executable, self.libpath)
