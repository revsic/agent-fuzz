import json
import os
import random
import shutil
import traceback
from dataclasses import dataclass, asdict
from uuid import uuid4

from agentfuzz.analyzer import Coverage, Factory, Fuzzer
from agentfuzz.harness.agent import Agent
from agentfuzz.harness.mutation.api import APICombMutator
from agentfuzz.harness.prompt import PROMPT_SUPPORTS, BaselinePrompt, PromptRenderer
from agentfuzz.logger import Logger


@dataclass
class Trial:
    trial: int = 0
    failure_agent: int = 0
    failure_parse: int = 0
    failure_compile: int = 0
    failure_fuzzer: int = 0
    failure_validity: int = 0
    success: int = 0
    converged: bool = False

    def dump(self) -> dict:
        """Serialize the states into the single dictionary.
        Returns:
            the states of `Trial`.
        """
        return asdict(self)

    @classmethod
    def load(cls, dumps: str | dict) -> "Trial":
        """Load from the dumps.
        Args:
            dumps: the dumpated states from the method `Trial.dump`.
        Returns:
            loaded states of `Trials`.
        """
        if isinstance(dumps, str):
            with open(dumps):
                dumps = json.load(dumps)
        return cls(**dumps)


class HarnessGenerator:
    """LLM Agent-based Harenss generation and fuzzing."""

    DEFAULT_LOGGER = Logger(
        os.environ.get("AGENTFUZZ_LOG_GENERATOR", "harness-gen.log"),
        verbose=True,
    )

    def __init__(
        self,
        factory: Factory,
        workdir: str | None = None,
        prompt: str | PromptRenderer = BaselinePrompt(),
        logger: Logger | None = None,
        _clear_previous_work: bool = False,
    ):
        """Initialize the harness generator.
        Args:
            factory: a project analyzer.
            workdir: a path to the working directory for harness generation pipeline.
                use `factory.workdir` if it is not provided.
            prompt: a prompt renderer for requesting a harness generation to the LLM.
            logger: a logger for harness generation, use `HarnessGenerator.DEFAULT_LOGGER` if it is not provided.
            _clear_previous_work: whether clear all previous works or not.
        """
        self.factory = factory
        self.workdir = workdir or factory.workdir
        if isinstance(prompt, str):
            assert (
                prompt in PROMPT_SUPPORTS
            ), f"invalid prompt name `{prompt}`, supports only `{', '.join(PROMPT_SUPPORTS)}`"
            prompt = PROMPT_SUPPORTS[prompt]
        self.prompt = prompt
        self.logger = logger or self.DEFAULT_LOGGER
        # working directories
        self._dir_state = os.path.join(self.workdir, "state")
        self._dir_work = os.path.join(self.workdir, "work")
        self._dir_harness = os.path.join(self.workdir, "harness")
        self._dir_failure_parse = os.path.join(
            self.workdir, "exceptions", "failure_parse"
        )
        self._dir_failure_compile = os.path.join(
            self.workdir, "exceptions", "failure_compile"
        )
        self._dir_failure_fuzzer = os.path.join(
            self.workdir, "exceptions", "failure_fuzzer"
        )
        self._working_dirs = [
            self._dir_state,
            self._dir_work,
            self._dir_harness,
            self._dir_failure_parse,
            self._dir_failure_compile,
            self._dir_failure_fuzzer,
        ]
        # TODO: temporal agent
        self._default_agent = Agent(_stack=["HarnessGenerator"])
        # WARNING: all works could be deleted if the flag on
        if _clear_previous_work:
            for dir_ in self._working_dirs:
                if not os.path.exists(dir_):
                    continue
                try:
                    shutil.rmtree(dir_)
                except:
                    pass

    def run(self, load_from_state: bool = True):
        """Generate the harenss and fuzzing.
        Args:
            load_from_state: load from the previous state if it is True.
        """
        # shortcut
        config = self.factory.config
        # construct the work directory
        for dir_ in self._working_dirs:
            os.makedirs(dir_, exist_ok=True)
        # listup the apis and types
        targets, types = self.factory.listup_apis(), self.factory.listup_types()
        # construct mutator
        if load_from_state:
            trial = Trial.load(os.path.join(self._dir_state, "latest-trial.json"))
            api_mutator = APICombMutator.load(
                os.path.join(self._dir_state, "latest-apimutator.json")
            )
        else:
            trial, api_mutator = Trial(), APICombMutator(targets)
        while True:
            if trial.converged or api_mutator.converge():
                trial.converged = True
                self.logger.log(f"Generation converged")
                break

            trial.trial += 1
            self.logger.log(f"Trial: {trial.trial}")
            apis = api_mutator.select(*config.comblen)
            self.logger.log(
                f"  APICombMutator.select: {json.dumps([g.signature() for g in apis], ensure_ascii=False)}"
            )
            # construct the prompt
            prompt = self.prompt.render(
                project=config.name,
                headers=[],  # TODO: Retrieve the system headers/imports
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
                trial.failure_agent += 1
                self.logger.log(f"  Failed to generate the harness: {result.error}")
                break
            # parse the code segment
            code = self._parse_code(result.response)
            if code is None:
                trial.failure_parse += 1
                uid = uuid4().hex
                with open(os.path.join(self._dir_failure_parse, uid), "w") as f:
                    f.write(result.response)
                self.logger.log(f"  Failed to parse the code (written as {uid})")
                continue
            # unpack
            _ext, code = code
            # write to the work directory
            filename = f"{trial.trial}.{config.ext}".rstrip(".")
            path = os.path.join(self._dir_work, filename)
            with open(path, "w") as f:
                f.write(code)
            self.logger.log(f"  Success to parse the code: work/{filename}")
            # check the validity in runtime
            fuzzer: Fuzzer
            try:
                fuzzer = self.factory.compiler.compile(path)
            except Exception as e:
                uid = uuid4().hex
                with open(os.path.join(self._dir_failure_compile, uid), "w") as f:
                    f.write(traceback.format_exc())
                trial.failure_compile += 1
                self.logger.log(
                    f"  Failed to compile the harness: {e} (written as {uid})"
                )
                break

            retn: int | None | Exception
            try:
                retn = fuzzer.run(
                    config.corpus_dir,
                    config.fuzzdict,
                    wait_until_done=True,
                    timeout=config.timeout,
                )
            except Exception as e:
                uid = uuid4().hex
                with open(os.path.join(self._dir_failure_fuzzer, uid), "w") as f:
                    f.write(traceback.format_exc())
                trial.failure_fuzzer += 1
                self.logger.log(f"  Failed to run the fuzzer: {e} (written as {uid})")
                break

            cov = fuzzer.coverage()
            # feedback to api mutator
            api_mutator.feedback(cov)
            # check the harness validity
            if (invalid := self._check_validity(path, retn, cov)) is None:
                trial.failure_validity += 1
                self.logger.log(f"  Invalid harness: {invalid}")
                break

            with open(os.path.join(self.workdir, "harness", filename), "w") as f:
                f.write(code)
            trial.success += 1
            self.logger.log(
                f"Success to generate the harness, written in harness/{filename}"
            )

    def _choose(self, items: list, n: int) -> list:
        """Simple implementation of `np.random.choice`.
        Args:
            items: a list.
            n: the number of the items to choose.
        Returns:
            n-sized list of randomly shuffled elements(non-duplicated).
        """
        # shallow copy
        items = [*items]
        # shuffle
        random.shuffle(items)
        return items[:n]

    def _parse_code(self, response: str) -> tuple[str | None, str] | None:
        """Parse the codes from the LLM response.
        Args:
            response: a given LLM response.
        Returns:
            a tuple of a language specifier and the corresponding code if found.
            None if failed to found a code segment from the given response.
        """
        # parse the code segment
        if (i := response.find("```")) < 0:
            return None
        response = response[i + 3 :]
        if (i := response.find("```")) < 0:
            return None
        # split ext
        ext, *lines = response[:i].split("\n")
        return ext.strip() or None, "\n".join(lines)

    def _check_validity(
        self, path: str, retn: int | None | Exception, cov: Coverage
    ) -> str | None:
        """Validate the harness.
        Args:
            path: a path to the harness source code.
            retn: a return code of the fuzzer compiled with the harness.
            cov: a coverage description about the fuzzer run.
        Returns:
            None if the given harness is valid, otherwise return the reason why the given harness is invalid.
        """
        # TODO: validate the harness
        return None
