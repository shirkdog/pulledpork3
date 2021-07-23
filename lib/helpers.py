import os.path
from shutil import rmtree

from . import logger


################################################################################
# Logging
################################################################################

log = logger.Logger()


################################################################################
# WorkingDirectory - Temporary directory helper
################################################################################

class WorkingDirectory(object):

    def __init__(self, temp_path, dir_name, cleanup_on_exit=True):
        '''
        Setup the working directory and structure
        '''

        # Save the bits
        self.temp_path = temp_path
        self.dir_name = dir_name
        self.path = os.path.join(self.temp_path, self.dir_name)
        self.downloaded_path = os.path.join(self.path, 'downloaded_rulesets')
        self.extracted_path = os.path.join(self.path, 'extracted_rulesets')
        self.so_rules_path = os.path.join(self.path, 'so_rules')
        self.cleanup_on_exit = cleanup_on_exit

        # Prepare things
        self._setup()

    def __repr__(self):
        return f'WorkingDirectory(path:{self.path}, cleanup_on_exit:{self.cleanup_on_exit})'

    def __del__(self):
        '''
        Clean up the temprary folder if required
        '''

        # Not cleaning up?
        if not self.cleanup_on_exit:
            log.verbose(f'Not deleting working directory: {self.path}')
            return

        log.verbose(f'Attempting to delete working directory: {self.path}')
        try:
            rmtree(self.path)
        except Exception as e:
            log.warning(f'Unable to delete working directory: {e}')
        else:
            log.verbose(' - Successfully deleted working directory')

    def _setup(self):
        '''
        Create the directory structure we'll be using
        '''

        log.verbose(f'Setting up the working directory structure in: {self.path}')

        # Create all the directories
        try:
            os.mkdir(self.path)
            os.mkdir(self.downloaded_path)
            os.mkdir(self.extracted_path)
            os.mkdir(self.so_rules_path)
        except Exception as e:
            log.error(f'Setup of the working directory failed: {e}')
        else:
            log.verbose(f' - Successfully setup the working directory')
