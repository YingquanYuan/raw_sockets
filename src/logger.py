import logging as L
import sys
from collections import defaultdict

init = False

LEVELS = defaultdict(lambda: L.DEBUG, {
    0: L.ERROR,
    1: L.WARN,
    2: L.INFO,
    3: L.DEBUG,
})

formatter = L.Formatter('[%(levelname)s] %(asctime)s %(name)s: %(message)s',
                        '%Y-%m-%d %H:%M:%S')


def init_logger(logfile, verbosity):
    """
    verbose - logging level map:
    0 - ERROR
    1 - WARN
    2 - INFO
    3 - DEBUG
    """
    global init
    logger = L.getLogger()
    logger.setLevel(LEVELS[verbosity])
    handler = L.StreamHandler(sys.stdout)
    if logfile:
        handler = L.FileHandler(logfile, mode='w')
    handler.setLevel(LEVELS[verbosity])
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    init = True


def get_logger(name):
    if not init:
        raise ValueError("The logger has not been initialized")
    return L.getLogger(name)
