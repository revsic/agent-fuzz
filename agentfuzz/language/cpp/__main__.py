import argparse

from agentfuzz.generator import HarnessGenerator
from agentfuzz.language.cpp.supports import CppConfig, CppProject


def run(
    projdir: str,
    srcdir: str,
    include_dir: str | list[str] | None = None,
):
    """Run the harness generation.
    Args:
        projdir: a path to the project directory.
        srcdir: a path to the source code directory.
        include_dir: a path to the directory for preprocessing `#include` macro.
    """
    config = CppConfig(
        projdir,
        srcdir=srcdir,
        postfix=(".h", ".hpp", ".hxx"),
        include_dir=include_dir or srcdir,
    )
    project = CppProject(projdir, config)
    HarnessGenerator(project).run()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--projdir", default="./cpp")
    parser.add_argument("--srcdir")
    args = parser.parse_args()
    run(args.projdir, args.srcdir)


if __name__ == "__main__":
    main()
