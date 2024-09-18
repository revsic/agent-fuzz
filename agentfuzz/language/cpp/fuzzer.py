import subprocess
import tempfile

from agentfuzz.analyzer.dynamic import Compiler, Fuzzer


class LibFuzzer(Fuzzer):
    """Libfuzzer wrapper."""

    def __init__(self, path: str):
        """Initialize the fuzzer wrapper.
        Args:
            path: a path to the executable file.
        """
        self.path = path

    def run(self):
        return super().run()

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
        libpath: str | list[str],
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
