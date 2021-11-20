from logging import Logger, Formatter, handlers
from queue import Queue
from constants import *


# configure the root logger
root_logger = logging.getLogger("")
root_logger.setLevel(LOG_LEVEL)

# configure the general formatter
formatter = logging.Formatter(
    "%(asctime)s : %(name)s : %(levelname)s : %(funcName)s : %(message)s"
    )


def get_new_logger(name: str, parent_logger: Logger = root_logger):
    return parent_logger.getChild(name.upper())


def get_stream_handler(formatter: Formatter = formatter):
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(formatter)
    return stream_handler


def get_file_handler(file_name: str, file_mode: str = LOG_FILE_MODE, formatter: Formatter = formatter):
    file_handler = logging.FileHandler(
                f"logs/{file_name.lower()}.log",
               file_mode 
            )
    file_handler.setFormatter(formatter)
    return file_handler