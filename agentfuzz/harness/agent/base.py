import json
from dataclasses import dataclass

import litellm

from agentfuzz.harness.agent.logger import Logger


class Agent:
    """Template for a LLM Agent."""

    @dataclass
    class Response:
        response: str | None
        messages: list[dict[str, str]]
        turn: int | None
        error: str | None = None

    def __init__(self, logger: Logger | None = None, _stack: list[str] | None = None):
        """Initialize the agent.
        Args:
            logger: a LLM message logger.
        """
        self.logger = logger or Logger.DEFAULT
        self._stack = _stack

    def run(
        self,
        model: str,
        messages: list[dict[str, str]],
        tools: dict[str, callable] | None = None,
        temperature: float = 0.7,
        max_turns: int = 30,
        _seed: int = 1024,
    ) -> "Agent.Response":
        """Run the LLM AI Agent.
        Args:
            model: the name of the llm model, reference litellm.
            messages: a list of human-LLM conversation.
            tools: a list of tools LLM can call.
            temperature: distribution sharpening factor.
            max_turns: the maximum number of the turns between human and LLM.
        """
        self.logger.log(
            {
                "request": {
                    "model": model,
                    "messages": messages,
                    "tools": list(tools) if isinstance(tools, dict) else tools,
                    "temperature": temperature,
                    "max_turns": max_turns,
                    "_seed": _seed,
                }
            }
        )
        # single conversation if tool does not exist
        if tools is None:
            response = litellm.completion(
                model=model,
                messages=messages,
                temperature=temperature,
                seed=_seed,
            )
            (choice,) = response.choices
            return self.Response(
                response=choice.message.content,
                messages=messages + [choice.model_dump()],
                turn=None,
            )

        # check whether the given model supports function calling API.
        if not litellm.supports_function_calling(model=model):
            msg = f"the given model `{model}` does not support function calling by litellm"
            self.logger.log({"error": msg})
            return self.Response(
                response=None,
                messages=messages,
                turn=None,
                error=msg,
            )
        # convert into json schema
        converted = {
            key: litellm.utils.function_to_dict(fn) for key, fn in tools.items()
        }
        for turn in range(max_turns):
            # call LLM
            response = litellm.completion(
                model=model,
                messages=messages,
                tools=converted,
                tool_choice="auto",
                temperature=temperature,
                seed=_seed,
            )
            (choice,) = response.choices
            # if agent does not call the functions/tools
            if choice.message.tool_calls is None:
                return self.Response(
                    response=choice.message.content,
                    messages=messages + [choice.model_dump()],
                    turn=turn,
                )
            # for supporting parallel tool calls
            for req in choice.message.tool_calls:
                # macro
                def _append(msg: str):
                    msg = {
                        "tool_call_id": req.id,
                        "role": "tool",
                        "name": req.function.name,
                        "content": msg,
                    }
                    messages.append(msg)
                    self.logger.log(msg)

                # if given tool is undefined
                if req.function.name not in tools:
                    _append(
                        f"error: undefined function `{req.function.name}`, available only `{', '.join(tools)}`"
                    )
                    continue
                # load the arguments
                args: dict[str, any]
                try:
                    args = json.loads(req.function.arguments)
                    retn = tools[req.function.name](**args)
                except json.JSONDecodeError as e:
                    _append(
                        f"error: exception occured during parsing arguments, `{e}`",
                    )
                    continue
                except Exception as e:
                    _append(
                        f"error: exception occured during calling the function, `{e}`",
                    )
                    continue
                # append the message
                _append(json.dumps(retn))
        # if agent does not respond the answer
        msg = f"iteration exceeds the given maximum number of the turns of conversation, {max_turns}"
        self.logger.log({"error": msg})
        return self.Response(
            None,
            messages=messages,
            turn=max_turns,
            error=msg,
        )
