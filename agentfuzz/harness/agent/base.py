import json
import traceback
from dataclasses import asdict, dataclass

import litellm

from agentfuzz.harness.agent.logger import AgentLogger
from agentfuzz.harness.validator import Success

# dollars per token, (input tokens, output tokens)
## Oct.05, 2024.
_million = 1_000_000
PRICING = {
    "gpt-4o-mini": (0.150 / _million, 0.600 / _million),
    "gpt-4o-mini-2024-07-18": (0.150 / _million, 0.600 / _million),
    "gpt-4o": (5.0 / _million, 15.00 / _million),
    "gpt-4o-2024-08-06": (2.50 / _million, 10.00 / _million),
    "gpt-4o-2024-05-13": (5.00 / _million, 15.00 / _million),
    "chatgpt-4o-latest": (5.00 / _million, 15.00 / _million),
    "gpt-4-turbo": (10.00 / _million, 30.00 / _million),
    "gpt-4-turbo-2024-04-09": (10.00 / _million, 30.00 / _million),
}


class Agent:
    """Template for a LLM Agent."""

    @dataclass
    class Response:
        response: str | None
        messages: list[dict[str, str]]
        turn: int | None
        error: str | None = None
        billing: float | None = None
        validated: Success | None = None

    def __init__(
        self, logger: AgentLogger | None = None, _stack: list[str] | None = None
    ):
        """Initialize the agent.
        Args:
            logger: a LLM message logger.
        """
        self.logger = logger or AgentLogger.DEFAULT
        self._stack = _stack

    def _compute_pricing(
        self, response: litellm.types.utils.ModelResponse
    ) -> float | None:
        """Compute the pricing from the response.
        Args:
            response: litellm response.
        Returns:
            pricing if computable, otherwise None.
        """
        if response.model not in PRICING:
            return None

        per_input, per_output = PRICING[response.model]
        return (
            per_input * response.usage.prompt_tokens
            + per_output * response.usage.completion_tokens
        )

    def pre_call(self, fn: str, args: dict):
        """Hook before call the tool.
        Args:
            fn: the name of the tool to call.
            args: the keyword arguments. you can update it inplacely.
        """
        pass

    def post_call(self, fn: str, args: dict, retn: any) -> Response | None:
        """Hook after call the tool.
        Args:
            fn: the name of the tool called.
            args: the keyword arguments.
            retn: the return value from the tool call.
        Returns:
            `Agent.Response` if you want to stop agent-iteration and return the response instantly.
            None for keep iteration.
        """
        return None

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
            try:
                response = litellm.completion(
                    model=model,
                    messages=messages,
                    temperature=temperature,
                    seed=_seed,
                )
            except:
                return self.Response(
                    response=None,
                    messages=messages,
                    turn=None,
                    error=traceback.format_exc(),
                )
            (choice,) = response.choices
            self.logger.log(response.model_dump())
            return self.Response(
                response=choice.message.content,
                messages=messages + [choice.message.model_dump()],
                turn=None,
                billing=self._compute_pricing(response),
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
        converted = [
            {"type": "function", "function": litellm.utils.function_to_dict(fn)}
            for fn in tools.values()
        ]
        total_price = None
        for turn in range(max_turns):
            # call LLM
            try:
                response = litellm.completion(
                    model=model,
                    messages=messages,
                    tools=converted,
                    tool_choice="auto",
                    temperature=temperature,
                    seed=_seed,
                )
            except:
                return self.Response(
                    response=None,
                    messages=messages,
                    turn=turn,
                    error=traceback.format_exc(),
                    billing=total_price,
                )
            (choice,) = response.choices
            self.logger.log(response.model_dump())
            messages.append(choice.message.model_dump())
            if (_price := self._compute_pricing(response)) is not None:
                total_price = (total_price or 0.0) + _price
            # if agent does not call the functions/tools
            if choice.message.tool_calls is None:
                return self.Response(
                    response=choice.message.content,
                    messages=messages,
                    turn=turn,
                    billing=total_price,
                )
            # for supporting parallel tool calls
            for req in choice.message.tool_calls:
                # macro
                def _append(msg: str, _debug: str | None = None):
                    msg = {
                        "tool_call_id": req.id,
                        "role": "tool",
                        "name": req.function.name,
                        "content": msg,
                    }
                    messages.append(msg)
                    self.logger.log({**msg, "_debug": _debug})

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
                    # hook before call
                    self.pre_call(req.function.name, args)
                    retn = tools[req.function.name](**args)
                    # hook after call
                    instant_msg = self.post_call(req.function.name, args, retn)
                except json.JSONDecodeError as e:
                    _append(
                        f"error: exception occured during parsing arguments, `{e}`",
                        {
                            "args": req.function.arguments,
                            "traceback": traceback.format_exc(),
                        },
                    )
                    continue
                except Exception as e:
                    _append(
                        f"error: exception occured during calling the function, `{e}`",
                        {"args": args, "traceback": traceback.format_exc()},
                    )
                    continue
                # append the message
                _append(json.dumps(retn, ensure_ascii=False))
                # if iteration needs to be halted
                if instant_msg is not None:
                    # force update
                    instant_msg.messages = messages
                    instant_msg.turn = turn
                    instant_msg.billing = total_price
                    self.logger.log(
                        {
                            "post_call": {
                                "function": req.function.name,
                                "args": args,
                                "instant_msg": asdict(instant_msg),
                            }
                        }
                    )
                    return instant_msg

        # if agent does not respond the answer
        msg = f"iteration exceeds the given maximum number of the turns of conversation, {max_turns}"
        self.logger.log({"error": msg})
        return self.Response(
            None,
            messages=messages,
            turn=max_turns,
            error=msg,
            billing=total_price,
        )
