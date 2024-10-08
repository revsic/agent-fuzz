import random

from agentfuzz.analyzer import APIGadget, TypeGadget, Factory
from agentfuzz.harness.agent import Agent, AgentLogger
from agentfuzz.harness.prompt import BaselinePrompt, PromptRenderer, PROMPT_SUPPORTS


class LLMBaseline:
    """LLM baseline for supporting harness generation."""

    def __init__(
        self,
        factory: Factory,
        agent: Agent | None = None,
        prompt: str | PromptRenderer = BaselinePrompt(),
        _agent_logger: str | AgentLogger | None = None,
        _verbose: bool = True,
        _stack: list[str] | None = None,
    ):
        """Initialize the LLM supports.
        Args:
            factory: the project analyzer.
            agent: a LLM agent for generating the fuzzing harness.
            prompt: prompt renderer for rendering the informations to a instruction prompt.
        """
        self.factory = factory

        if agent is None:
            if isinstance(_agent_logger, str):
                _agent_logger = AgentLogger(_agent_logger, _verbose)
            agent = Agent(_agent_logger, _stack)
        self.agent = agent

        if isinstance(prompt, str):
            if prompt not in PROMPT_SUPPORTS:
                self.agent.logger.log(
                    {
                        "prompt": f"WARNING: invalid prompt name {prompt}, use baseline prompt",
                        "possibles": list[PROMPT_SUPPORTS],
                    }
                )
                prompt = "baseline"
            prompt = PROMPT_SUPPORTS[prompt]
        self.prompt = prompt

    def run(
        self,
        targets: list[APIGadget],
        apis: list[APIGadget] = [],
        types: list[TypeGadget] = [],
        **kwargs,
    ) -> Agent.Response:
        """Render the given informations into an instruction prompt then request to LLM.
        Args:
            targets: the targeted apis.
            apis: a list of apis contained in the library.
            types: a list of types contained in the library.
        Returns:
            a response from the LLM agent.
        """
        return self.request(self.render(targets, apis, types))

    def request(self, prompt: list[dict[str, str]]) -> Agent.Response:
        """Request to generate a harness with the given instruction prompt.
        Args:
            prompt: the OpenAI-format instruction prompt.
        Returns:
            a response from the LLM agent.
        """
        return self.agent.run(self.factory.config.llm, prompt)

    def render(
        self,
        targets: list[APIGadget],
        apis: list[APIGadget] = [],
        types: list[TypeGadget] = [],
    ) -> list[dict[str, str]]:
        """Render the given informations into an instruction prompt.
        Args:
            targets: the targeted apis.
            apis: a list of apis contained in the library.
            types: a list of types contained in the library.
        Returns:
            OpenAI-format instruction prompt.
        """
        config = self.factory.config
        # retrieve only relative types
        retrieved = {}
        for target in targets:
            for gadget in self.factory.parser.retrieve_type(target, types):
                if gadget.signature() in retrieved:
                    continue
                retrieved[gadget.signature()] = gadget
        # render
        return self.prompt.render(
            project=config.name,
            headers=[],  # TODO: Retrieve the system headers/imports
            apis=(
                apis
                if len(apis) < config.max_apis
                else self._choose(apis, config.max_apis)
            ),
            types=list(retrieved.values()),
            combinations=targets,
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
