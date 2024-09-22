import os
import json

from pydantic import BaseModel

from agentfuzz.logger import Logger


class AgentLogger(Logger):
    """Logger for LLM Agent."""

    DEFAULT: "AgentLogger"

    def __init__(
        self,
        path: str = "agent.log",
        verbose: bool = True,
    ):
        """Initialize the logger.
        Args:
            path: a path to the log file.
            verbose: whether print to the terminal or not.
        """
        super().__init__(path, verbose)

    def log(self, msg):
        """Log the json-serializable object.
        Args:
            msg: a json serializable object, e.g. pydantic or dictionary, etc.
        """
        if isinstance(msg, BaseModel):
            msg = msg.model_dump()
        super().log(json.dumps(msg, indent=2, ensure_ascii=False))


AgentLogger.DEFAULT = AgentLogger(
    os.environ.get("AGENTFUZZ_LOG_AGENT", "agent.log"),
    verbose=True,
)
