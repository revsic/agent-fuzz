import os
import shutil
import tempfile
import traceback
from dataclasses import dataclass
from time import sleep, time

from tqdm.auto import tqdm

from agentfuzz.analyzer import APIGadget, Coverage, Factory, Fuzzer
from agentfuzz.logger import Logger


class ValidationError(Exception):
    """Super class of validation errors"""


@dataclass
class ParseError(ValidationError):
    """Error occurs during parse the code segment."""

    response: str
    description: str


@dataclass
class CompileError(ValidationError):
    """Error occurs during compile the source code."""

    path: str
    compile_error: str
    traceback: str


@dataclass
class FuzzerError(ValidationError):
    """Error occurs during fuzzer run."""

    exception: str
    traceback: str


@dataclass
class CoverageNotGrow(ValidationError):
    """If there are is no unique branch found while the fuzzer run"""

    cov_global: float
    cov_local: float


@dataclass
class CriticalPathNotHit(ValidationError):
    """If a parsed critical path is not fully covered by the fuzzer run"""

    critical_paths: list[list[tuple[APIGadget | str, int | None, str]]]

    def _render(self) -> list[str]:
        _name = lambda g: g if isinstance(g, str) else g.name
        return [
            f"[{', '.join(_name(gadget) + label for gadget, _, label in critical_path)}]"
            for critical_path in self.critical_paths
        ]


@dataclass
class Success:
    """Success to pass all harness validation tests."""

    path: str
    fuzzer: Fuzzer
    cov_lib: Coverage
    cov_fuzz: Coverage
    validated_paths: list[list[tuple[APIGadget | str, int | None]]]


class HarnessValidator:
    def __init__(
        self,
        factory: Factory,
        apis: list[APIGadget] | None = None,
        logger: Logger | None = None,
    ):
        self.factory = factory
        if apis is None:
            apis = factory.listup_apis()
        self.apis = apis
        self.logger = logger

    def validate(
        self,
        response: str,
        global_cov: Coverage,
        workdir: str | None = None,
        corpus_dir: str | None = None,
        fuzzdict: str | None = None,
        verbose: bool = False,
        batch_size: int | None = None,
    ) -> ValidationError | Success:
        """Validate a requested harness.
        Args:
            response: a source code of the requested harness.
            global_cov: a coverage descriptor to compare with the fuzzer run.
            workdir: a path to the working directory, use `tempfile.mkdtemp()` if not given.
            corpus_dir: a path to the corpus directory, use `self.factory.config.corpus_dir` if not given.
            fuzzdict: a path to the AFL-style fuzzing dictionary, use `self.factory.config.fuzzdict` if not given.
            verbose: whether use tqdm on collecting coverage or not.
        Returns:
            `ValidationError` if error occured.
            `Success` if given harness pass all the tests.
        """
        # shortcut
        config = self.factory.config
        ## 1. Parse code segment
        retn = self.check_code_segment(response)
        if isinstance(retn, ValidationError):
            return retn

        # unpack
        ext, code = retn
        # construct a working directory
        workdir = workdir or tempfile.mkdtemp()
        os.makedirs(workdir, exist_ok=True)
        # write the code
        filename = f"source.{config.ext}".rstrip(".")
        path = os.path.join(workdir, filename)
        if os.path.exists(path):
            self.logger.log(f"WARNING: duplicated path, {path}.")
        with open(path, "w") as f:
            f.write(code)
        if self.logger is not None:
            self.logger.log(f"Success to parse the code: work/{filename}.")

        ## 2. Compilability
        retn = self.check_compile(path)
        if isinstance(retn, ValidationError):
            return retn

        fuzzer: Fuzzer = retn
        if self.logger is not None:
            self.logger.log(f"Success to compile the code: work/{filename}.")

        ## 3. Fuzzer run
        start = time()
        retn = self.check_fuzzer_run(
            fuzzer,
            corpus_dir or config.corpus_dir,
            fuzzdict or config.fuzzdict,
            config.timeout,
            config.timeout_unit,
        )
        if isinstance(retn, ValidationError):
            return retn
        if self.logger is not None:
            self.logger.log(f"Success to run the fuzzer({time() - start:.2f}s).")

        ## 4. Collect coverage
        start = time()
        cov_lib, cov_fuzz = self.collect_coverage(
            fuzzer,
            corpus_dir or config.corpus_dir,
            fuzzdict or config.fuzzdict,
            verbose=verbose,
            batch_size=batch_size,
        )
        if self.logger is not None:
            self.logger.log(
                f"Success to collect the coverage({time() - start:.2f}s, lib: {cov_lib.coverage_branch * 100:.2f}%, fuzzer: {cov_fuzz.coverage_branch * 100:.2f}%)."
            )

        ## 5. Coverage growth
        retn = self.check_cov_growth(global_cov, cov_lib)
        if isinstance(retn, ValidationError):
            return retn
        if self.logger is not None:
            self.logger.log(f"Coverage was grown while last fuzzer run.")

        ## 6. Critical Path Coverage
        retn = self.check_critical_path_hit(path, cov_fuzz, self.apis)
        if isinstance(retn, ValidationError):
            return retn
        if self.logger is not None:
            self.logger.log(f"Fully covered critical path found.")

        validated_paths = retn

        # success to pass all tests
        if self.logger is not None:
            self.logger.log(f"Succesfully validated the requested harness.")
        return Success(
            path=path,
            fuzzer=Fuzzer,
            cov_lib=cov_lib,
            cov_fuzz=cov_fuzz,
            validated_paths=validated_paths,
        )

    def check_code_segment(self, response: str) -> tuple[str | None, str] | ParseError:
        """Parse the codes from the LLM response.
        Args:
            response: a given LLM response.
        Returns:
            a tuple of a language specifier and the corresponding code if found.
            ParseError if failed to found a code segment from the given response.
        """
        # parse the code segment
        if (i := response.find("```")) < 0:
            return ParseError(response, "ParseError: cannot find a ```")
        response = response[i + 3 :]
        if (i := response.find("```")) < 0:
            return ParseError(response, "ParseError: cannot find a pair of ```")
        # split ext
        ext, *lines = response[:i].split("\n")
        return ext.strip() or None, "\n".join(lines)

    def check_compile(self, path: str) -> Fuzzer | CompileError:
        """Compile the source code.
        Args:
            path: a path to a source code.
        Returns:
            compiled fuzzer or compile error if failed to compile the given source code.
        """
        try:
            return self.factory.compiler.compile(path)
        except Exception as e:
            return CompileError(path, str(e), traceback.format_exc())

    def check_fuzzer_run(
        self,
        fuzzer: Fuzzer,
        corpus_dir: str | None = None,
        fuzzdict: str | None = None,
        timeout: float = 600,
        interval: float = 60,
    ) -> None | FuzzerError:
        """Check the fuzzer can be run without errors.
        Args:
            fuzzer: the target fuzzer.
            corpus_dir: a path to the directory containing corpus.
            fuzzdict: a path to the AFL-style fuzzing dictionary.
            timeout: fuzzing timeout.
            interval: an interval between the adjacent growth checks.
        Returns:
            None if coverage growth, otherwise `FuzzerError`.
        """
        try:
            fuzzer.run(
                corpus_dir,
                fuzzdict,
                wait_until_done=False,
                timeout=timeout,
                runs=None,
            )
            last_cov = 0
            # initial trial
            sleep(interval)
            while fuzzer.poll() is None:
                if last_cov >= (current := fuzzer.track()):
                    break
                last_cov = current
                sleep(interval)
            fuzzer.halt()
        except Exception as e:
            return FuzzerError(e, traceback.format_exc())

        return None

    def collect_coverage(
        self,
        fuzzer: Fuzzer,
        corpus_dir: str | None = None,
        fuzzdict: str | None = None,
        verbose: bool = False,
        batch_size: int | None = None,
    ) -> tuple[Coverage, Coverage]:
        """Check the fuzzer can be run without errors.
        Args:
            fuzzer: the target fuzzer.
            corpus_dir: a path to the directory containing corpus.
            fuzzdict: a path to the AFL-style fuzzing dictionary.
        Returns:
            coverage about the library and fuzzer itself.
        """
        cov_lib, cov_fuzz = Coverage(), Coverage()
        # minimize the corpus first
        if minimized := fuzzer.minimize(corpus_dir, tempfile.mkdtemp()):
            shutil.rmtree(corpus_dir)
            shutil.move(minimized, corpus_dir)
        # run individual corpora
        _corpus_dirs = []
        _workdir = tempfile.mkdtemp()
        for corpora in os.listdir(corpus_dir):
            _corpus_dir = os.path.join(_workdir, corpora)
            os.makedirs(_corpus_dir, exist_ok=True)
            shutil.copy(
                os.path.join(corpus_dir, corpora),
                os.path.join(_corpus_dir, "CORPORA"),
            )
            _corpus_dirs.append(_corpus_dir)
        # batch supports
        iter_ = fuzzer.batch_run(
            _corpus_dirs,
            batch_size=batch_size or os.cpu_count(),
            fuzzdict=fuzzdict,
            timeout=None,
            runs=1,
            return_cov=True,
        )
        if verbose:
            iter_ = tqdm(iter_, total=len(_corpus_dirs))
        for _corpus_dir, retn, covs in iter_:
            if covs is None:
                if self.logger is not None:
                    corpora = os.path.basename(_corpus_dir)
                    self.logger.log(f"Failed to run the corpora {corpora}: {retn}")
                continue
            # merge to global cov
            _cov_lib, _cov_fuzz = covs
            cov_lib.merge(_cov_lib)
            cov_fuzz.merge(_cov_fuzz)

        return cov_lib, cov_fuzz

    def check_cov_growth(
        self, global_: Coverage, local: Coverage
    ) -> None | CoverageNotGrow:
        """Check whether the unique branch was found.
        Args:
            global_, local: the global and a local coverage.
        Returns:
            None if the unique branches found, otherwise `CoverageNotGrow`.
        """
        if set(local.flat(nonzero=True)) - set(global_.flat(nonzero=True)):
            return None
        return CoverageNotGrow(
            cov_global=global_.coverage_branch, cov_local=local.coverage_branch
        )

    def check_critical_path_hit(
        self,
        path: str,
        cov: Coverage,
        gadgets: list[APIGadget] | None = None,
    ) -> list[list[tuple[str | APIGadget, int | None]]] | CriticalPathNotHit:
        """Check whether the fuzzer cover full critical path.
        Args:
            path: a path to the source code file.
            cov: a coverage descriptor about the fuzzer run.
            gadgets: a list of apis of interest, use `self.apis` if it is not given.
        Returns:
            the fully covered critical paths if exist, otherwise `CriticalPathNotHit` error.
        """
        critical_paths = self.factory.parser.extract_critical_path(
            path, gadgets=gadgets or self.apis
        )
        validated_paths = [
            critical_path
            for critical_path in critical_paths
            if all(
                cov.cover_lines(path, lineno)
                for _, lineno in critical_path
                if lineno is not None
            )
        ]
        if validated_paths:
            return validated_paths

        _label = lambda l: (
            "(invalid lineno)"
            if l is None
            else (
                "(invalid filename)"
                if (c := cov.cover_lines(path, l)) is None
                else ("(hit)" if c else "(miss)")
            )
        )
        return CriticalPathNotHit(
            critical_paths=[
                [(gadget, lineno, _label(lineno)) for gadget, lineno in critical_path]
                for critical_path in critical_paths
            ],
        )
