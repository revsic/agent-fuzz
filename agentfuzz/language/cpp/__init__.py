from agentfuzz.language.cpp.supports import CppProject, CppConfig


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--projdir", default="./cpp")
    parser.add_argument("--srcdir")
    parser.add_argument("--libpath")
    args = parser.parse_args()
    CppProject(
        args.projdir,
        CppConfig(args.srcdir, libpath=args.libpath),
    ).run()


if __name__ == "__main__":
    main()
