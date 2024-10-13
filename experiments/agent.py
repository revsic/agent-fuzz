import json
import os
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import litellm

from agentfuzz.analyzer import APIGadget, Coverage, Factory, Fuzzer, TypeGadget
from agentfuzz.harness import HarnessGenerator, HarnessValidator
from agentfuzz.harness.agent import Agent, AgentLogger
from agentfuzz.harness.llm import LLMBaseline, BaselinePrompt
from agentfuzz.harness.validator import (
    CompileError,
    CoverageNotGrow,
    CriticalPathNotHit,
    FuzzerError,
    ParseError,
    Success,
    ValidationError,
)
from agentfuzz.language import CppSupports
from agentfuzz.logger import Logger


@dataclass
class APINotCovered(ValidationError):
    covered: set[str]
    requested: set[str]


class AugmentedValidator(HarnessValidator):
    def check_compile(
        self, path: str, targets: list[APIGadget]
    ) -> Fuzzer | CompileError | APINotCovered:
        """Compile the source code.
        Args:
            path: a path to a source code.
            targets: a list of the requested apis.
        Returns:
            Fuzzer: compiled fuzzer
            CompileError: compile error if failed to compile the given source code.
        """
        # compilability
        try:
            fuzzer = self.factory.compiler.compile(path)
        except Exception as e:
            return CompileError(path, str(e), traceback.format_exc())
        # coverage check
        critical_paths = self.factory.parser.extract_critical_path(path)
        covered = set(
            (api if isinstance(api, str) else api.name)
            for apis in critical_paths
            for api, _ in apis
        )
        if all(target.name in covered for target in targets):
            return fuzzer

        return APINotCovered(covered, set(target.name for target in targets))


class AgentHarnessGeneration(Agent):
    def __init__(
        self,
        factory: Factory,
        agent_logger: AgentLogger | str | None = None,
        valid_logger: Logger | str | None = None,
        batch_size: int | None = None,
    ):
        """Initialize agent.
        Args:
            factory: a project analyzer.
            agent_logger, valid_logger: loggers for agent and harness validator.
        """
        self.factory = factory
        if isinstance(agent_logger, str):
            agent_logger = AgentLogger(agent_logger)
        if isinstance(valid_logger, str):
            valid_logger = Logger(valid_logger)
        self.state = {}
        self.validator = HarnessValidator(factory, logger=valid_logger)
        self.batch_size = batch_size
        super().__init__(agent_logger)

    def tools(self):
        return {
            "find_definition": self.find_definition,
            "find_references": self.find_references,
            "read_file": self.read_file,
            "validate": self.validate,
        }

    def _read_file(self, found: dict[str, list[int | range]]):
        """Read the code snippet from the file.
        Args:
            found: a map of file path and target lineno.
        Returns:
            read snippet.
        """
        return [
            {
                "file": filename,
                "found": [
                    {
                        "line": line,
                        "content": (
                            read := self.read_file(filename, line, num_lines=1)
                        ).get("contents", read),
                    }
                    for _listed in lines
                    for line in ([_listed] if isinstance(_listed, int) else _listed)
                ],
            }
            for filename, lines in found.items()
        ]

    def find_definition(self, symbol: str) -> dict:
        """Find the definition about the given symbol from the project.
        You will see a list of found definitions `content`, path `file` and line numbers `line`.
        For example, [{"file": "cjson/cJSON.c", "found": [{"line": 94, "content": "static cJSON_bool parse_number(cJSON * const item, parse_buffer * const input_buffer)"}]}]
        However, if the symbol does not exist, {"error": "no results found."} will be returned.

        Parameters
        ----------
        symbol : str
            The target symbol, for example, "parse_number"
        """
        found = self.factory.tags.find_definition(symbol)
        if not found:
            return {"error": "no results found."}
        return self._read_file(found)

    def find_references(self, symbol: str) -> dict:
        """Find the references about the given symbol.
        You will see a list of found references `content`, path `file` and line numbers `line`.
        For example, [{"file": "cjson/cJSON.c", "found": [{"line": 1363, "content": "        return parse_number(item, input_buffer);"}]}]
        However, if the symbol does not exist, {"error": "no results found."} will be returned.

        Parameters
        ----------
        symbol : str
            The target symbol, for example, "parse_number"
        """
        found = self.factory.tags.find_references(symbol)
        if not found:
            return {"error": "no results found."}
        return self._read_file(found)

    def read_file(self, filename: str, lineno: int, num_lines: int = 50) -> dict:
        """Read the `filename` file and returns the `num_lines` lines around line `lineno`.
        You will see the `num_lines` lines from the specified source file `filename` around `lineno`.
        For example, {"content": "...\n    {\n        return parse_number(item, input_buffer);\n...", "line_start": 1338, "line_end": 1388}
        However, if the file does not exist, {"error": "file does not exist"} will be returned.
        Or if given line number is out of the source file, {"error": "the given lineno is out of the file"} will be returned.

        Parameters
        ----------
        filename : str
            The name of the file, for example, "cjson/cJSON.c"
        lineno: int
            The line number, center point, e.g. 1363
        num_lines: int
            The number of the lines to read, e.g. 50
        """
        path = os.path.join(self.factory.config.srcdir, filename)
        if not os.path.exists(path):
            return {"error": "file does not exist"}
        with open(path, errors="replace") as f:
            lines = f.read().split("\n")
            start = max(lineno - num_lines // 2, 0)
            read_ = lines[start : start + num_lines]
            if not read_:
                return {
                    "error": f"the given lineno {lineno} is out of the file `{filename}`"
                }
            return {
                "contents": "\n".join(read_),
                "line_start": start,
                "line_end": start + len(read_),
            }

    def validate(self, harness: str) -> dict:
        """Validate the given harness.
        Validation consists of seven steps.
        1. Parse the code segment from the requested harness. The process only uses the code segment enclosed within ``` ```.
        2. Compile the code segment into a runnable fuzzer.
        3. Run the fuzzer.
        4. Check whether the coverage has increased more than the global coverage.
        5. Check whether all APIs have been hit.
        If all steps pass, you will see a "success" flag in the response.
        However, if something is wrong, you will see an error flag and the steps where the error occurs.
        Then you should fix the harness to ensure the steps pass and retry the validation.

        Parameters
        ----------
        harness : str
            The requested harness, for example,
            ```cpp
            #include <stdlib.h>
            #include <stdint.h>

            extern "C" int LLVMFuzzerTestOneInput(const uint8_t data, size_t size) {
                // your harness here
            }
            ```
        """
        assert "targets" in self.state, "pass the list of the requested apis"
        assert "workdir" in self.state, "specify the working directory"
        match self.validator.validate(
            harness,
            self.state["targets"],  # required
            self.state.get("cov") or Coverage(),
            self.state["workdir"],  # required
            self.state.get("corpus_dir"),
            self.state.get("fuzzdict"),
            batch_size=self.batch_size,
        ):
            case ParseError() as err:
                return {
                    "error": "parse",
                    "description": err.description,
                    "suggestion": "Wrap your code in ``` blocks correctly.",
                }
            case CompileError() as err:
                return {
                    "error": "compile",
                    "description": err.compile_error,
                    "suggestion": """
Analyze the compile error and correct the harness.
You may call `find_definition`, `find_references`, and `read_file` to gather more information about the APIs.
Alternatively, you can fix the error directly without retrieval.
""",
                }
            case APINotCovered() as err:
                return {
                    "error": "api-not-used",
                    "description": f"""
Some of the APIs are not used in the harness; you should include all APIs.
- Here are the requested APIs: {json.dumps(sorted(err.requested))}
- Here are the APIs that the harness does not use: {json.dumps(sorted(err.requested - err.covered))}
""",
                    "suggestion": "Consider use cases that involve the APIs not used in the harness, and modify the harness to include those APIs.",
                }
            case FuzzerError() as err:
                return {
                    "error": "fuzzer-run",
                    "description": err.exception,
                    "_traceback": err.traceback,
                }
            case CoverageNotGrow() as err:
                return {
                    "error": "coverage-growth",
                    "description": f"current coverage: {err.cov_local * 100:.2f}%, global coverage: {err.cov_global * 100:.2f}",
                    "suggestion": """
This validation step (coverage-growth) is designed to check whether a new unique branch was covered, rather than simply measuring coverage growth in a naive way. We do not recommend using additional APIs. Instead of increasing the number of APIs, we suggest thoroughly reviewing and modifying the harness. Here are some possible review questions:
1. Are you making sufficient use of the input byte stream from LLVMFuzzerTestOneInput: `const uint8_t *data`, or are you relying on hardcoded data or your own data generation stream? We recommend utilizing the input byte stream rather than generating your own input or using hardcoded test cases.
2. Are the APIs in the harness organically connected? For example, in Python, if you create a dictionary `a = dict(**data)`, you could then test the `del` operation with `for k in a: del a[k]`. This would be a well-organized case. However, if you simply test `del a["exampleKey"]` without checking if exampleKey exists in a, the test case may not be properly covered. Additionally, this approach only covers the specific case of `exampleKey` and does not fully utilize the input stream data.

Based on these types of questions, list the areas you want to review in the harness, conduct the review, and then rewrite the harness to achieve more unique branch coverage
""".strip(),
                }
            case CriticalPathNotHit() as err:
                return {
                    "error": "api-hit",
                    "description": "- " + "\n- ".join(err._render()),
                    "suggestion": """
This validation step (api-hit) is designed to check whether the APIs are correctly invoked during the fuzzing of the harness. We recommend thoroughly reviewing the harness and modifying it to ensure that all APIs from the harness are invoked. Here is a possible review question:

Q. Does the control flow of your harness sufficiently cover the API calls? For example, in Python, if you create a dictionary `a = dict(**data)`, you might construct a control flow like `if "exampleKey" in a: delete_item(a, "exampleKey")` to test the `delete_item` API. However, since the input byte stream `data` is provided by the fuzzer, in most cases, `exampleKey` will not be a member of `a`. As a result, this control flow will rarely invoke `delete_item`. A better approach would be to modify it to `for key in a: delete_item(a, key)` to ensure the `delete_item` API is tested. This will invoke the `delete_item` API, allowing the `api-hit` round to be passed.

Based on these types of questions, list the areas you want to review in the harness, conduct the review, and then rewrite the harness to ensure that all APIs are invoked.
""",
                }
            case Success() as succ:
                return {"success": True, "validated": succ}

    def run(
        self, model: str, messages: list[dict[str, str]], **kwargs
    ) -> Agent.Response:
        """Generate a harness.
        Args:
            model: the name of the model, e.g. gpt-4o-2024-07-18.
            messages: an OpenAI format instruction prompt.
        Returns:
            response from the agent.
        """
        tools = self.tools()
        self.logger.log(
            {
                "available tools": {
                    key: litellm.utils.function_to_dict(fn) for key, fn in tools.items()
                }
            }
        )
        self.state = kwargs
        return super().run(model, messages, tools)

    def post_call(self, fn: str, args: dict, retn: any) -> Agent.Response | None:
        if fn == "validate" and isinstance(retn, dict) and retn.get("success"):
            validated: Success = retn.pop("validated")
            # TODO: support a json serialization for `Success`
            validated.fuzzer = None
            return Agent.Response(
                response=None,
                messages=None,  # it will be updated by agent base
                turn=None,
                validated=validated,
            )

        return None


class AgentLLM(LLMBaseline):
    def run(
        self,
        targets: list[APIGadget],
        apis: list[APIGadget] = [],
        types: list[TypeGadget] = [],
        **kwargs,
    ) -> Agent.Response:
        return self.agent.run(
            model=self.factory.config.llm,
            messages=self.render(targets, apis, types),
            targets=targets,
            **kwargs,
        )


_AGENT_MD = """
##### system
Act as a C++ langauge Developer, write a fuzz driver that follow user's instructions.
The prototype of fuzz dirver is: `extern "C" int LLVMFuzzerTestOneInput(const uint8_t data, size_t size)`.

The fuzz dirver should focus on the usage of the {{PROJECT}} library, and several essential aspects of the library are provided below.

Here are the APIs exported from {{PROJECT}}. You are encouraged to use any of the following APIs once you need to create, initialize or destory variables:
----------------------
{{APIS}}
----------------------

Here are the custom types declared in {{PROJECT}}. Ensure that the variables you use do not violate declarations:
----------------------
{{CONTEXT}}
----------------------

##### user
Create a C++ language program step by step by using {{PROJECT}} library APIs and following the instructions below:
1. Here are several APIs in {{PROJECT}}. Specify an event that those APIs could achieve together, if the input is a byte stream of {{PROJECT}}.
{{COMBINATIONS}};
2. Complete the LLVMFuzzerTestOneInput function to achieve this event by using those APIs. Each API should be called at least once, if possible.
3. The input data and its size are passed as parameters of LLVMFuzzerTestOneInput: `const uint8_t *data` and `size_t size`. They must be consumed by the {{PROJECT}} APIs.
4. Once you need a `FILE *` variable to read the input data, using `FILE * in_file = fmemopen((void *)data, size, "rb")` to produce a `FILE *` variable.
   Once you need a `FILE *` variable to write output data, using `FILE * out_file = fopen("output_file", "wb")` to produce a `FILE *` variable.
5. Once you need a `int` type file descriptor, using `fileno(in_file)` or `fileno(out_file)` to produce a file descriptor for reading or writing. 
6. Once you just need a string of file name, directly using "input_file" or "output_file" as the file name.
7. Release all allocated resources before return.

Before writing a harness, call `find_definition`, `find_references`, and `read_file` to gain a sufficient understanding of the given *several* APIs.
(We do not recommend querying all APIs exported from {{PROJECT}}. Only query the necessary APIs, and if more information is needed, perform additional queries when required.)

After you writing a fuzz harness that contains those *several* APIs, call `validate` to verify your harness.
You should fix the harness to pass all validation steps over several iterations.

At each fixing step, analyze the feedback, write your thoughts step-by-step, and rewrite the harness to call `validate` again.

If you understand, start to understand the project, write a harness and call `validate`.
"""


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="cjson")
    parser.add_argument("--stamp", default=None)
    args = parser.parse_args()
    # target project
    benchmark = os.path.abspath(f"{__file__}/../../benchmark/{args.target}")
    # construct project
    stamp = args.stamp or datetime.now(timezone(timedelta(hours=9))).strftime(
        "%Y.%m.%dT%H:%M"
    )
    workdir = f"./workspace/{args.target}/{stamp}"
    # load config
    config = CppSupports._Config.load_from_yaml(os.path.join(benchmark, "config.yaml"))
    config.srcdir = os.path.join(benchmark, config.srcdir)
    if config.fuzzdict is not None:
        config.fuzzdict = os.path.join(benchmark, config.fuzzdict)
    if config.corpus_dir is not None:
        config.corpus_dir = os.path.join(benchmark, config.corpus_dir)
    if config.libpath is not None:
        config.libpath = os.path.join(benchmark, config.libpath)
    config.include_dir = [os.path.join(benchmark, dir_) for dir_ in config.include_dir]
    project = CppSupports(workdir, config)

    generator = HarnessGenerator(
        project.factory,
        project.workdir,
        llm=AgentLLM(
            project.factory,
            AgentHarnessGeneration(
                project.factory,
                agent_logger=os.path.join(workdir, "agent.log"),
                valid_logger=os.path.join(workdir, "validator.log"),
            ),
            BaselinePrompt(_AGENT_MD),
        ),
        logger=os.path.join(workdir, "harness-gen.log"),
    )
    generator.run(load_from_state=True)
