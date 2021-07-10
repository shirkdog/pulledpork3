'''
TODO
Realistically this should probably use native Python logging, but this at least
helps clean up some of the code in the meantime.
'''
import sys
from enum import IntEnum


class Levels(IntEnum):
    ERROR = -1
    WARNING = 0
    INFO = 1
    VERBOSE = 2
    DEBUG = 3


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'  # a nice yellowish warning
    FAIL = '\033[91m'       # RED
    ENDC = '\033[0m'    # end the color (end of line)
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Global Logger defaults
DEFAULT_LEVEL = Levels.INFO
DEFAULT_HALT_ON_WARN = True


class Logger(object):

    # Set global defaults
    _level = DEFAULT_LEVEL
    _halt_on_warn = DEFAULT_HALT_ON_WARN

    def __init__(self, level=None, halt_on_warn=None):

        # Allow overrides to global defaults during instantiation
        if level is not None:
            self.level = level
        if halt_on_warn is not None:
            self.halt_on_warn = halt_on_warn

    # Ensure the properties changes affect the values globally

    @classmethod
    def _set_level(cls, level):
        cls._level = level

    @classmethod
    def _set_halt_on_warn(cls, halt_on_warn):
        cls._halt_on_warn = halt_on_warn

    # Properties

    @property
    def level(self):
        return self._level

    @level.setter
    def level(self, level):
        self._set_level(level)

    @property
    def halt_on_warn(self):
        return self._halt_on_warn

    @halt_on_warn.setter
    def halt_on_warn(self, halt_on_warn):
        self._set_halt_on_warn(halt_on_warn)

    # Logging methods

    def error(self, msg):

        # Not currently logging this level? Move on, otherwise print msg
        if self.level < Levels.ERROR:
            return

        # Using colors!
        print(f'{Colors.FAIL}ERROR: {msg}{Colors.ENDC}')

        # This was critical
        sys.exit(-2)

    def warning(self, msg):

        # Not currently logging this level? Move on, otherwise print msg
        if self.level < Levels.WARNING:
            return

        # Using colors!
        print(f'{Colors.WARNING}WARNING: {msg}{Colors.ENDC}')

        # Halt if requested
        if self.halt_on_warn:
            sys.exit(-1)

    def info(self, msg):

        # Not currently logging this level? Move on, otherwise print msg
        if self.level < Levels.INFO:
            return
        print(msg)

    def verbose(self, msg):

        # Not currently logging this level? Move on, otherwise print msg
        if self.level < Levels.VERBOSE:
            return
        print(msg)

    def debug(self, msg):

        # Not currently logging this level? Move on, otherwise print msg
        if self.level < Levels.DEBUG:
            return
        print(msg)
