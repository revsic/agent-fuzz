from agentfuzz.analyzer import Factory


class HarnessGenerator:
    """LLM Agent-based Harenss generation and fuzzing."""

    def __init__(self, factory: Factory):
        """Initialize the harness generator.
        Args:
            factory: a project analyzer.
        """
        self.factory = factory

    def run(self):
        """Generate the harenss and fuzzing."""
        pass
