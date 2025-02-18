import os

import litellm

from agentfuzz.analyzer import APIGadget, Factory, TypeGadget
from agentfuzz.analyzer.dynamic.coverage import Coverage
from agentfuzz.harness.agent import Agent, AgentLogger
from agentfuzz.harness.generator import HarnessGenerator
from agentfuzz.harness.llm import BaselinePrompt, LLMBaseline
from agentfuzz.harness.validator import (
    CompileError,
    CoverageNotGrow,
    CriticalPathNotHit,
    FuzzerError,
    HarnessValidator,
    ParseError,
    Success,
)
from agentfuzz.logger import Logger


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
        assert "workdir" in self.state, "specify the working directory"
        match self.validator.validate(
            harness,
            self.state.get("cov") or Coverage(),
            self.state.get("workdir"),
            self.state.get("corpus_dir"),
            self.state.get("fuzzdict"),
            batch_size=self.batch_size,
        ):
            case ParseError() as err:
                return {"error": "parse", "description": err.description}
            case CompileError() as err:
                return {"error": "compile", "description": err.compile_error}
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
                }
            case CriticalPathNotHit() as err:
                return {
                    "error": "api-hit",
                    "description": "- " + "\n- ".join(err._render()),
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
        """Hook for instant response after validation success.
        Args:
            fn: the name of the tool called.
            retn: the return value from the tool call.
        Returns:
            instant response when validation success, otherwise None.
        """
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

    def pre_llm(self, messages: list[dict[str, str]]) -> list[dict[str, str]]:
        """Hook for maintining the conversation concise.
        Args:
            messages: previous conversation.
        Returns:
            simplified conversation (remove middle of validation tool calls)
        """
        # group in tool call conversations
        grouped = []
        while messages:
            flag = False
            for i, msg in enumerate(messages):
                if msg["role"] == "tool":
                    flag = True
                if flag and msg["role"] != "tool":
                    break
            if not flag or msg["role"] == "tool":
                grouped.append(messages)
                break
            grouped.append(messages[:i])
            messages = messages[i:]
        assert grouped
        # find the first validation
        for i, (fst, *_) in enumerate(grouped):
            if fst["role"] == "assistant" and any(
                call["function"]["name"] == "validate"
                for call in fst.get("tool_calls", [])
            ):
                break
        # remove the middle of validation calls.
        return [
            msg
            for group in grouped[:i] + grouped[max(i, len(grouped) - 2) :]
            for msg in group
        ]


class AgentLLM(LLMBaseline):
    def run(
        self,
        targets: list[APIGadget],
        apis: list[APIGadget] = [],
        types: list[TypeGadget] = [],
        **kwargs,
    ) -> Agent.Response:
        return self.agent.run(
            self.factory.config.llm, self.render(targets, apis, types), **kwargs
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


class AgenticHarnessGenerator(HarnessGenerator):
    def __init__(
        self,
        factory: Factory,
        workdir: str | None = None,
        logger: Logger | str | None = None,
        _agent_logger: AgentLogger | str | None = None,
        _valid_logger: Logger | str | None = None,
        _clear_previous_work: bool = False,
        _prompt: str | None = None,
    ):
        super().__init__(
            factory,
            workdir,
            AgentLLM(
                factory,
                AgentHarnessGeneration(
                    factory,
                    agent_logger=_agent_logger or os.path.join(workdir, "agent.log"),
                    valid_logger=_valid_logger
                    or os.path.join(workdir, "validator.log"),
                ),
                BaselinePrompt(_prompt or _AGENT_MD),
            ),
            logger=logger or os.path.join(workdir, "harness-gen.log"),
            _clear_previous_work=_clear_previous_work,
        )
