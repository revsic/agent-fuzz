from datetime import datetime, timedelta, timezone


class Logger:
    """Logger baseline"""

    def __init__(
        self,
        path: str,
        verbose: bool = True,
        _timezone: int | timezone = 9,
        _verbose_method: callable = print,
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
        self._verbose_method = _verbose_method

    def log(self, msg: str):
        """Write the log into the file and verbose to the terminal if verbose option is on.
        Args:
            msg: a log message.
        """
        timestamp = datetime.now(self._timezone).strftime("%Y.%m.%dT%H:%M:%S")
        msg = f"[{timestamp}] {msg}\n"
        with open(self.path, "a") as f:
            f.write(msg)
        if self.verbose:
            self._verbose_method(msg)
