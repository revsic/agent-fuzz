import os

from agentfuzz.analyzer import APIGadget, TypeGadget


class PromptRenderer:
    """Render a markdown-format instruction prompt to a list of messages."""

    def __init__(self, markdown: str, sep: str = "#####"):
        """Initialize the renderer.
        Args:
            markdown: a markdown format instruction prompt or a path to the such markdownn file.
            sep: a seperator for splitting the prompt into the user-agent turns.
        Example:
            A markdown-format instruction prompt could be like:
            ```md
            ##### system
            This is the system prompt.

            ##### user
            This is the first user prompt.

            ##### assistant
            And this is the first assistant prompt.

            ##### user
            This is the second user prompt.
            ```

            Then seperator should be a `#####`.
            A renderer will parse it to:
            ```json
            [
              {
                "role": "system",
                "content": "This is the system prompt."
              },
              {
                "role": "user",
                "content": "This is the first user prompt."
              },
              ...
            ]
            ```
        """
        if os.path.exists(markdown):
            with open(markdown) as f:
                markdown = f.read()
        self.markdown = markdown
        self.sep = sep

    def render(self, **kwargs) -> list[dict[str, str]]:
        """Render the markdown-formst instruction prompt with reducing the template.
        Args:
            kwargs: reducing targets.
                if a template "{{PROJECT}}" is inside the prompt, then `render(project="cjson")` will reduce the `{{PROJECT}}` into `cjson`.
        Returns:
            rendered messages.
        """
        return self.parse_md(self.markdown, self.sep, **kwargs)

    def _render_gadget(
        self, apis: str | list[APIGadget | TypeGadget | str], sep: str = "\n"
    ) -> str:
        """Render the API or type gadgets into a single string.
        Args:
            apis: a list of apis/type gadgets.
            sep: seperator between a adjacent gadgets.
        Returns:
            serialized string.
        """
        if isinstance(apis, str):
            return apis
        return sep.join(
            api if isinstance(api, str) else api.signature() for api in apis
        )

    @staticmethod
    def parse_md(contents: str, sep: str = "#####", **kwargs) -> list[dict[str, str]]:
        """Parse the markdown-format instruction prompts.
        Args:
            contents: markdown-format instruction prompts.
            sep: turn-seperator.
            kwargs: placeholder and their values for reducing the instruction prompt template.
        Returns:
            OpenAI-format chat conversation history.
        """
        messages = []
        for turn in contents.split(sep):
            if turn.strip() == "":
                continue
            role, *inst = turn.split("\n")
            inst = "\n".join(inst).strip()
            # reduce
            for key, value in kwargs.items():
                inst = inst.replace("{{" + key.upper() + "}}", value)
            messages.append({"role": role.strip(), "content": inst})
        return messages
