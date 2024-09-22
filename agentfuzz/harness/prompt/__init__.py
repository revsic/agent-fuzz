from agentfuzz.harness.prompt.baseline import BaselinePrompt, PromptRenderer


PROMPT_SUPPORTS: dict[str, PromptRenderer] = {
    "baseline": BaselinePrompt(),
    "promptfuzz": BaselinePrompt(),
}
