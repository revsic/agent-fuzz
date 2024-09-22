from agentfuzz.language.cpp.supports import CppSupports


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--projdir", default="./cpp")
    parser.add_argument("--config")
    args = parser.parse_args()
    CppSupports.from_yaml(args.projdir, args.config).run()


if __name__ == "__main__":
    main()
