import json
import os
import random
import shutil
from dataclasses import dataclass, asdict

from agentfuzz.analyzer import Coverage, Factory
from agentfuzz.harness.agent import Agent
from agentfuzz.harness.mutation import APIMutator
from agentfuzz.harness.prompt import PROMPT_SUPPORTS, BaselinePrompt, PromptRenderer
from agentfuzz.harness.validator import (
    HarnessValidator,
    ParseError,
    CompileError,
    FuzzerError,
    CoverageNotGrow,
    CriticalPathNotHit,
    Success,
)
from agentfuzz.logger import Logger


class _Serializable:
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


@dataclass
class Trial(_Serializable):
    trial: int = 0
    failure_agent: int = 0
    failure_parse: int = 0
    failure_compile: int = 0
    failure_fuzzer: int = 0
    failure_coverage: int = 0
    failure_critical_path: int = 0
    success: int = 0
    converged: bool = False
    cost: float = 0.0


@dataclass
class Covered(Coverage, _Serializable):
    pass


class HarnessGenerator:
    """LLM Agent-based Harenss generation and fuzzing."""

    Validator = HarnessValidator

    DEFAULT_LOGGER = Logger(
        os.environ.get("AGENTFUZZ_LOG_GENERATOR", "harness-gen.log"),
        verbose=True,
    )

    def __init__(
        self,
        factory: Factory,
        workdir: str | None = None,
        prompt: str | PromptRenderer = BaselinePrompt(),
        logger: Logger | str | None = None,
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
        if isinstance(logger, str):
            logger = Logger(logger)
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
        # isolate the corpus directory
        corpus_dir = os.path.join(self.workdir, "corpus")
        if not os.path.exists(corpus_dir):
            shutil.copytree(config.corpus_dir, corpus_dir)

        # listup the apis and types
        targets, types = self.factory.listup_apis(), self.factory.listup_types()

        # construct mutator
        _latest = os.path.join(self._dir_state, "latest.json")
        if load_from_state and os.path.exists(_latest):
            trial, covered, api_mutator = self.load(_latest)
        else:
            trial, covered, api_mutator = Trial(), Covered(), APIMutator(targets)

        # construct validator
        validator = self.Validator(self.factory, targets, self.logger)

        # start iteration
        while not trial.converged and trial.cost < config.quota:
            # save the latest state
            self.dump(trial, covered, api_mutator, path=_latest)
            self._log_stats(trial, covered, config.quota)

            trial.trial += 1
            self.logger.log(f"Trial: {trial.trial}")
            apis = api_mutator.select(covered, *config.comblen)
            self.logger.log(
                f"  APIMutator.select: {json.dumps([g.signature() for g in apis], ensure_ascii=False)}"
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
            trial.cost += result.billing or 0.0
            if result.error:
                trial.failure_agent += 1
                self.logger.log(f"  Failed to generate the harness: {result.error}")
                break

            # construct harness-level working directory
            workdir = os.path.join(self._dir_work, str(trial.trial))
            os.makedirs(workdir, exist_ok=True)

            # exception handler
            def _handle_error(errfile: str, error: str, errdir: str, log: str):
                with open(os.path.join(workdir, errfile), "w") as f:
                    f.write(error)
                shutil.move(workdir, os.path.join(errdir, str(trial.trial)))
                self.logger.log(log)

            # validate
            match validator.validate(
                result.response,
                covered,
                workdir,
                corpus_dir,
                config.fuzzdict,
                verbose=True,
            ):
                case ParseError() as err:
                    trial.failure_parse += 1
                    _handle_error(
                        "failure_parse.txt",
                        err.description,
                        self._dir_failure_parse,
                        f"Failed to parse the code: work/{trial.trial}",
                    )

                case CompileError() as err:
                    trial.failure_compile += 1
                    _handle_error(
                        "failure_compile.txt",
                        err.traceback,
                        self._dir_failure_compile,
                        f"Failed to compile the harness {trial.trial}: {err.compile_error}",
                    )

                case FuzzerError() as err:
                    trial.failure_fuzzer += 1
                    _handle_error(
                        "failure_fuzzer.txt",
                        err.traceback,
                        self._dir_failure_fuzzer,
                        f"Failed to run the fuzzer {trial.trial}: {err.exception}",
                    )

                case CoverageNotGrow() as err:
                    trial.failure_coverage += 1
                    msg = f"FP: Critical path did not grow, current: {err.cov_local * 100:.2f}%, global: {err.cov_global * 100:.2f}%"
                    _handle_error(
                        "failure_cov_growth.txt", msg, self._dir_failure_fuzzer, msg
                    )

                case CriticalPathNotHit() as err:
                    trial.failure_critical_path += 1
                    _name = lambda g: g if isinstance(g, str) else g.name
                    _critical_paths = "\n  ".join(
                        f"[{', '.join(_name(gadget) + label for gadget, _, label in critical_path)}]"
                        for critical_path in err.critical_paths
                    )
                    msg = f"FP: Critical path did not hit,\n  {_critical_paths}"
                    _handle_error(
                        "failure_critical_path.txt", msg, self._dir_failure_fuzzer, msg
                    )

                case Success() as succ:
                    trial.success += 1
                    # copy the file
                    filename = f"{trial.trial}.{config.ext}"
                    filepath = os.path.join(self._dir_harness, filename)
                    shutil.copy(succ.path, filepath)
                    # merge coverage
                    covered.merge(succ.cov_lib)
                    # append to mutator
                    for path in succ.validated_paths:
                        api_mutator.append_seeds(filepath, succ.cov_lib, path)

                    self.logger.log(
                        f"Success to generate the harness, written in harness/{filename}"
                    )

            # stop condition check
            if self.trial_converge(trial, covered) or api_mutator.converge():
                trial.converged = True
                self.logger.log(f"Generation converged")
                break

        self._log_stats(trial, covered, config.quota)
        # save the last state
        self.dump(trial, covered, api_mutator, path=_latest)

    def dump(
        self,
        trial: Trial,
        covered: Covered,
        api_mutator: APIMutator,
        path: str | None = None,
    ):
        """Save the state of the harness generator.
        Args:
            trial, covered, api_mutator: the states of harness generator.
        """
        with open(path or os.path.join(self._dir_state, "latest.json"), "w") as f:
            json.dump(
                {
                    "trial": trial.dump(),
                    "coverage": covered.dump(),
                    "mutator-api": api_mutator.dump(),
                },
                f,
            )

    def load(self, path: str | None = None):
        """Load the states of the harness generator.
        Returns:
            loaded states.
        """
        with open(path or os.path.join(self._dir_state, "latest.json")) as f:
            latest = json.load(f)
        return (
            Trial.load(latest["trial"]),
            Covered.load(latest["coverage"]),
            APIMutator.load(latest["mutator-api"]),
        )

    def _log_stats(self, trial: Trial, covered: Coverage, quota: float):
        """Log the current statistics.
        Args:
            trial, covered: generation trials and the global coverages.
            quota: a limit for LLM API billing, in dollars.
        """
        self.logger.log(
            f"""
Success: {trial.success}/{trial.trial} (TP Rate: {trial.success / max(trial.trial, 1) * 100:.4f}, Quota {trial.cost:.2f}/{quota}$)
  Coverage: branch {covered.coverage_branch * 100:.4f}%
  Failure: agent {trial.failure_agent}, parse {trial.failure_parse}, compile: {trial.failure_compile}, fuzzer {trial.failure_fuzzer}, coverage {trial.failure_coverage}, critical-path: {trial.failure_critical_path}
""".strip()
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

    def trial_converge(self, trial: Trial, cov: Covered) -> bool:
        """Check the generation trial converge.
        Args:
            trial: the statistics about current harness generation trials.
            cov: the statistics about the fuzzer coverage.
        Returns:
            whether harness generator enough to try or not.
        """
        # trivial case
        return trial.success > 0
