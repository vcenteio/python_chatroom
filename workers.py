from queue import Queue
from logging import Logger
from message import QueueSignal


class Worker:
    def __init__(self, procedure):
        self.procedure = procedure

    active = True

    def __call__(self, caller, q: Queue, log: Logger, *args):
        while self.active:
            item = q.get()
            if item is QueueSignal._terminate_thread:
                self.active = False
                log.debug(
                    f"{self.procedure.__name__}: "\
                    "Got terminate thread signal; "\
                        "active flag: set -> clear"
                    )
            else:
                self.procedure(caller, item, *args)
            q.task_done()
        log.debug(f"Exiting {self.procedure.__name__} loop.")