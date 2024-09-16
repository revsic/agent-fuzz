from agentfuzz.language.cpp.supports import CppProject


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--projdir", default="./cpp")
    parser.add_argument("--srcdir")
    args = parser.parse_args()
    CppProject.template(args.projdir, args.srcdir).run()


if __name__ == "__main__":
    main()
