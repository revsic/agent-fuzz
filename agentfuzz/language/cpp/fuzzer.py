import subprocess
import tempfile
from time import time

from agentfuzz.analyzer.dynamic import Compiler, Fuzzer


class LibFuzzer(Fuzzer):
    """Libfuzzer wrapper."""

    def __init__(self, path: str, minimize_corpus: bool = True):
        """Initialize the fuzzer wrapper.
        Args:
            path: a path to the executable file.
            minimize_corpus: minimize the corpus if given is True, using a `-merge=1` option.
        """
        self.path = path
        self.minimize_corpus = minimize_corpus

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
        timeout: float = 300.0,
    ):
        """Run the compiled harness with given corpus directory and the fuzzer dictionary.
        Args:
            corpus_dir: a path to the directory containing fuzzing inputs (corpus).
            fuzzdict: a path to the fuzzing dictionary file.
            timeout: a time limit.
        """
        # minimize the corpus first
        if self.minimize_corpus:
            if minimized := self._minimize_corpus(corpus_dir):
                corpus_dir = minimized
        # run the fuzzer
        cmd = [self.path]
        if corpus_dir is not None:
            cmd.append(corpus_dir)
        if fuzzdict is not None:
            cmd.extend(["-dict", fuzzdict])

        proc = subprocess.Popen(
            cmd,
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
        )

        start = time()
        while proc.poll() is None:
            if time() - start > timeout:
                break
            with open("log.txt", "ab") as f:
                f.write(proc.stdout.read())
        retn = proc.poll()
        # kill if it is not finished
        if retn is None:
            proc.kill()
        return retn

    def coverage(self):
        return super().coverage()


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
        libpath: str | list[str] = [],
        include_dir: str | list[str] | None = None,
        cxx: str = "clang++",
        cxxflags: list[str] = _CXXFLAGS,
    ):
        """Prepare for the compile.
        Args:
            libpath: a path to the library path.
            include_dir: a path to the directory for preprocessing #include macro.
            cxx: a path to the clang++ compiler.
            cxxflags: additional compiler arguments.
        """
        self.libpath: list[str] = libpath
        if isinstance(libpath, str):
            self.libpath = [libpath]

        self.include_dir: list[str] | None = include_dir
        if isinstance(include_dir, str):
            self.include_dir = [include_dir]

        self.cxx = cxx
        self.cxxflags = cxxflags

    def compile(self, srcfile: str, _outpath: str | None = None) -> LibFuzzer:
        """Compile the given harness to fuzzer object.
        Args:
            srcfile: a path to the source code file.
        Returns:
            fuzzer object.
        """
        _include_args = []
        if self.include_dir is not None:
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
                *self.libpath,  # linkage
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

        return LibFuzzer(executable)
