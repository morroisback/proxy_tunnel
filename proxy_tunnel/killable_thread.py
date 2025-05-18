import sys

from threading import Thread
from types import FrameType
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from _typeshed import TraceFunction


class KillableThread(Thread):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.run = self.run
        self.__run_backup = None
        self.killed = False

    def start(self) -> None:
        self.__run_backup = self.run
        self.run = self.__run
        super().start()

    def __run(self) -> None:
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup

    def globaltrace(self, frame: FrameType, event: str, arg: Any) -> "TraceFunction | None":
        if event == "call":
            return self.localtrace
        else:
            return None

    def localtrace(self, frame: FrameType, event: str, arg: Any) -> "TraceFunction | None":
        if self.killed:
            if event == "line":
                raise SystemExit()
        return self.localtrace

    def kill(self) -> None:
        self.killed = True


def main() -> None:
    import logging
    import time

    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    def foo() -> None:
        while True:
            time.sleep(0.2)
            logger.info("thread running")

    thread = KillableThread(target=foo)
    thread.start()
    time.sleep(2)
    thread.kill()


if __name__ == "__main__":
    main()
