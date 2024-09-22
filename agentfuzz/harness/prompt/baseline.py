from agentfuzz.analyzer import APIGadget, TypeGadget
from agentfuzz.harness.prompt.renderer import PromptRenderer


_BASELINE_MD = """
##### system
Act as a C++ langauge Developer, write a fuzz driver that follow user's instructions.
The prototype of fuzz dirver is: `extern "C" int LLVMFuzzerTestOneInput(const uint8_t data, size_t size)`.

The fuzz dirver should focus on the usage of the {{PROJECT}} library, and several essential aspects of the library are provided below.
Here are the system headers included in {{PROJECT}}. You can utilize the public elements of these headers:
----------------------
{{HEADERS}}
----------------------

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
1. Here are several APIs in {{PROJECT}}. Specific an event that those APIs could achieve together, if the input is a byte stream of {{PROJECT}}' output data.
{{COMBINATIONS}};
2. Complete the LLVMFuzzerTestOneInput function to achieve this event by using those APIs. Each API should be called at least once, if possible.
3. The input data and its size are passed as parameters of LLVMFuzzerTestOneInput: `const uint8_t *data` and `size_t size`. They must be consumed by the {{PROJECT}} APIs.
4. Once you need a `FILE *` variable to read the input data, using `FILE * in_file = fmemopen((void *)data, size, "rb")` to produce a `FILE *` variable.
   Once you need a `FILE *` variable to write output data, using `FILE * out_file = fopen("output_file", "wb")` to produce a `FILE *` variable.
5. Once you need a `int` type file descriptor, using `fileno(in_file)` or `fileno(out_file)` to produce a file descriptor for reading or writing. 
6. Once you just need a string of file name, directly using "input_file" or "output_file" as the file name.
7. Release all allocated resources before return.
"""


class BaselinePrompt(PromptRenderer):
    """Baseline prompt from PromptFuzz[arXiv:2312.17677]"""

    def __init__(self, markdown: str = _BASELINE_MD):
        super().__init__(markdown, sep="#####")

    def render(
        self,
        project: str,
        headers: str | list[str],
        apis: str | list[APIGadget | str],
        types: str | list[TypeGadget | str],
        combinations: str | list[APIGadget | str],
    ):
        """Construct the baseline prompt, reference from promptfuzz.
        Args:
            project: the name of the current project, e.g. cJSON, libpcap, etc.
            headers: a list of system headers which is contained by the project.
            apis: a list of apis that llm can reference.
            types: a list of types that llm can reference, may contains the user-defined types.
            combinations: a list of apis that harness should consist of.
        """
        return super().render(
            project=project,  # {{PROJECT}}
            headers=(
                headers if isinstance(headers, str) else "\n".join(headers)
            ),  # {{HEADERS}}
            apis=self._render_gadget(apis),  # {{APIS}}
            context=self._render_gadget(types),  # {{CONTEXT}}
            combinations="    "
            + self._render_gadget(combinations, sep=",\n    "),  # {{COMBINATIONS}}
        )
