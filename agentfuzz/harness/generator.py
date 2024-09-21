import os
import random

from agentfuzz.analyzer import Factory, Fuzzer
from agentfuzz.harness.agent import Agent
from agentfuzz.harness.mutation.api import APICombMutator
from agentfuzz.harness.prompt.baseline import prompt_baseline


class HarnessGenerator:
    """LLM Agent-based Harenss generation and fuzzing."""

    def __init__(self, factory: Factory, workdir: str | None = None):
        """Initialize the harness generator.
        Args:
            factory: a project analyzer.
            workdir: a path to the working directory for harness generation pipeline.
                use `factory.workdir` if it is not provided.
        """
        self.factory = factory
        self.workdir = workdir or factory.workdir
        self._default_agent = Agent(_stack=["HarnessGenerator"])

    def run(self):
        """Generate the harenss and fuzzing."""
        # shortcut
        config = self.factory.config
        # construct the work directory
        os.makedirs(os.path.join(self.workdir, "work"), exist_ok=True)
        os.makedirs(os.path.join(self.workdir, "harness"), exist_ok=True)
        seeds = 0
        # listup the apis and types
        targets, types = self.factory.listup_apis(), self.factory.listup_types()
        # construct mutator
        api_mutator = APICombMutator(targets)
        # TODO: Support in range combination length
        comblen, _ = config.comblen
        while True:
            apis = api_mutator.select(comblen)
            # construct the prompt
            prompt = prompt_baseline(
                project=config.name,
                headers=[],  # TODO: Retrieve the system headers
                apis=(
                    targets
                    if len(targets) < config.max_apis
                    else self._choose(targets, config.max_apis)
                ),
                types=[
                    gadget
                    for api in apis
                    for gadget in self.factory.parser.retrieve_type(api, types)
                ],
                combinations=apis,
            )
            # generate the harness w/LLM
            result = self._default_agent.run(config.llm, prompt)
            if result.error:
                break
            # parse the code segment
            code = self._parse_code(result.response)
            if code is None:
                continue
            # unpack
            _ext, code = code
            # write to the work directory
            seeds += 1
            path = os.path.join(self.workdir, f"work/{seeds}.{config.ext}".rstrip("."))
            with open(path, "w") as f:
                f.write(code)
            # check the validity
            try:
                fuzzer = self.factory.compiler.compile(path)
                retn = fuzzer.run(
                    config.corpus_dir,
                    config.fuzzdict,
                    wait_until_done=True,
                    timeout=config.timeout,
                )
                cov = fuzzer.coverage()
                # feedback to api mutator
                api_mutator.feedback(cov)
                # check the harness validity
                if self._validate(path, retn, cov):
                    with open(
                        os.path.join(self.workdir, f"harness/{seeds}.{config.ext}"), "w"
                    ) as f:
                        f.write(code)
            except Exception as e:
                continue

            if api_mutator.converge():
                break

    def _choose(self, items: list, n: int) -> list:
        # shallow copy
        items = [*items]
        # shuffle
        random.shuffle(items)
        return items[:n]

    def _parse_code(self, response: str) -> tuple[str | None, str] | None:
        # parse the code segment
        if (i := response.find("```")) < 0:
            return None
        response = response[i + 3 :]
        if (i := response.find("```")) < 0:
            return None
        # split ext
        ext, *lines = response[:i].split("\n")
        return ext.strip() or None, "\n".join(lines)

    def _validate(self, path: str, retn: int | None | Exception, cov: any) -> bool:
        # TODO: validate the harness
        return True
