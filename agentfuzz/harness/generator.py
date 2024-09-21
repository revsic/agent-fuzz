import random

from agentfuzz.analyzer import Factory
from agentfuzz.harness.agent import Agent
from agentfuzz.harness.mutation.api import APICombMutator
from agentfuzz.harness.prompt.baseline import prompt_baseline


class HarnessGenerator:
    """LLM Agent-based Harenss generation and fuzzing."""

    def __init__(self, factory: Factory):
        """Initialize the harness generator.
        Args:
            factory: a project analyzer.
        """
        self.factory = factory
        self._default_agent = Agent(_stack=["HarnessGenerator"])

    def _choose(self, items: list, n: int) -> list:
        # shallow copy
        items = [*items]
        # shuffle
        random.shuffle(items)
        return items[:n]

    def run(self):
        """Generate the harenss and fuzzing."""
        # shortcut
        config = self.factory.config
        # listup the apis and types
        targets, types = self.factory.listup_apis(), self.factory.listup_types()
        # construct mutator
        api_mutator = APICombMutator(targets)
        # TODO: Support in range combination length
        comblen, _ = config.comblen
        # TODO: Add stop conditions
        while True:
            apis = api_mutator.select(comblen)
            prompt = prompt_baseline(
                project=config.name,
                headers=[],  # TODO: Retrieve the system headers
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
            response = self._default_agent.run(config.llm, prompt)
            if response.error:
                break
