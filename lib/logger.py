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
    _hidden_strings = []

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

    # This one is a little special... RO property, and must use
    #    .add_hidden_string() to add to global list

    @property
    def hidden_strings(self):
        return self._hidden_strings

    @classmethod
    def add_hidden_string(cls, some_str):
        cls._hidden_strings.append(some_str)

    def _sanitize(self, msg):
        '''
        Hide the strings present in the hidden_strings list
        '''

        # Work through the list, replacing each
        for some_str in self.hidden_strings:
            msg = msg.replace(some_str, '<hidden>')

        # Return final result
        return msg

    # Logging methods

    def _log(self, level, msg):
        '''
        Print the message as long we have a sufficient log level, and sanitize
        if required
        '''

        # Check the level
        if self.level < level:
            return

        # Sanitize the output unless we're at DEBUG
        if level < Levels.DEBUG:
            msg = self._sanitize(msg)

        # Print the message
        print(msg)

    def error(self, msg):
        '''
        Print the message as long we have a logging level at, or below, ERROR
        '''
        self._log(Levels.ERROR, f'{Colors.FAIL}ERROR: {msg}{Colors.ENDC}')

        # This was critical
        sys.exit(-2)

    def warning(self, msg):
        '''
        Print the message as long we have a logging level at, or below, WARNING
        '''
        self._log(Levels.WARNING, f'{Colors.WARNING}WARNING: {msg}{Colors.ENDC}')

        # Halt if requested
        if self.halt_on_warn:
            sys.exit(-1)

    def info(self, msg):
        '''
        Print the message as long we have a logging level at, or below, INFO
        '''
        self._log(Levels.INFO, msg)

    def verbose(self, msg):
        '''
        Print the message as long we have a logging level at, or below, VERBOSE
        '''
        self._log(Levels.VERBOSE, msg)

    def debug(self, msg):
        '''
        Print the message as long we have a logging level at, or below, DEBUG
        '''
        self._log(Levels.DEBUG, msg)
