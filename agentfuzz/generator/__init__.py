from agentfuzz.project import Project


class HarnessGenerator:
    """LLM Agent-based Harenss generation and fuzzing."""

    def __init__(self, project: Project):
        """Initialize the harness generator.
        Args:
            project: a project information/configuration.
        """
        self.project = project

    def run(self):
        """Generate the harenss and fuzzing."""
        pass
