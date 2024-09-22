import os

from agentfuzz.language import LANGUAGE_SUPPORT


def fuzzer(language: str, workdir: str, config: str):
    """Run the agent to fuzz the project.
    Args:
        language: a language of the target project, reference `agentfuzz.language.LANGUAGE_SUPPORT`.
        workdir: a path to the working directory.
        config: a path to the configuartion file.
    """
    assert (
        language in LANGUAGE_SUPPORT
    ), f"invalid language, agentfuzz only supports `{', '.join(LANGUAGE_SUPPORT)}`"
    # construct the working directory
    os.makedirs(workdir, exist_ok=True)
    # start fuzz
    project = LANGUAGE_SUPPORT[language].from_yaml(workdir, config)
    project.run()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--language",
        choices=list(LANGUAGE_SUPPORT),
        required=True,
        help="a language of the target project.",
    )
    parser.add_argument(
        "--workdir", required=True, help="a path to the working directory"
    )
    parser.add_argument(
        "--config", required=True, help="a path to the configuration file"
    )
    args = parser.parse_args()

    fuzzer(
        language=args.language,
        workdir=args.workdir,
        config=args.config,
    )
