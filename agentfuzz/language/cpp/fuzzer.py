from agentfuzz.analyzer.dynamic import Compiler, Fuzzer


class LibFuzzer(Fuzzer):
    """Libfuzzer wrapper."""

    def run(self):
        return super().run()

    def coverage(self):
        return super().coverage()


class Clang(Compiler):
    """Compile the C/C++ project with clang w/libfuzzer."""

    def compile(self, srcfile: str) -> LibFuzzer:
        return super().compile(srcfile)
