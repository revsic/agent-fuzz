import os
import subprocess

from agentfuzz.analyzer import Compiler
from agentfuzz.language.cpp.fuzzer import LibFuzzer


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
