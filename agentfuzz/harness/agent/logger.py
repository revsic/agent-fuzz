import os
import json
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel


class Logger:
    """Logger for LLM Agent."""

    DEFAULT: "Logger"

    def __init__(
        self,
        path: str = "agent.log",
        verbose: bool = True,
        _timezone: int | timezone = 9,
    ):
        """Initialize the logger.
        Args:
            path: path to the log file.
            verbose: whether print to the terminal or not.
        """
        self.path = path
        self.verbose = verbose
        if isinstance(_timezone, int):
            _timezone = timezone(timedelta(hours=_timezone))
        self._timezone = _timezone

    def log(self, msg):
        timestamp = datetime.now(self._timezone).strftime("%Y.%m.%dT%H:%M:%S")
        if isinstance(msg, BaseModel):
            msg = msg.model_dump()
        msg = f"[{timestamp}] {json.dumps(msg, indent=2, ensure_ascii=False)}\n"
        with open(self.path, "a") as f:
            f.write(msg)
        if self.verbose:
            print(msg)


Logger.DEFAULT = Logger(
    os.environ.get("LOGPATH", "agent.log"),
    verbose=True,
)
