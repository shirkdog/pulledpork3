from time import strftime, localtime
from tempfile import gettempdir

from . import logger


################################################################################
# Logging
################################################################################

log = logger.Logger()


################################################################################
# Constants
################################################################################

VALID_IPS_POLICIES = ['none', 'connectivity', 'balanced', 'security', 'max-detect']


################################################################################
# Config
################################################################################

class Config(object):

    # Save the start time for the app
    start_time = strftime('%Y.%m.%d-%H.%M.%S', localtime())

    # Target for the loaded config, defined values are defaults
    _config = {
        'community_ruleset': False,
        'registered_ruleset': False,
        'lightspd_ruleset': False,
        'snort_blocklist': False,
        'et_blocklist': False,
        'ips_policy': 'connectivity',
        'include_disabled_rules': False,
        'delete_temp_path': True,
    }

    # Map some of the methods from the _config dict to this class
    __contains__ = _config.__contains__
    __iter__ = _config.__iter__
    __getitem__ = _config.__getitem__
    get = _config.get
    items = _config.items
    keys = _config.keys

    # Supporting functions

    def __getattr__(self, key):
        '''
        Provide direct access to the dict via .key
        '''
        if key in self._config:
            return self._config[key]
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{key}'")

    def __setattr__(self, key, value):
        '''
        Update the _config dict when setting attributes to this config
        '''
        self._config[key] = value

    def defined(self, key):
        '''
        Return True or False whether a config key is defined
        '''
        res = self.get(key, None)
        if isinstance(res, bool):
            return True
        return bool(res)

    def load(self, config_file):
        '''
        Parse the config file line-by-line and populate _config
        '''

        log.debug(f'Entering: Config.load({config_file})')

        # Open the config and work through it line-by-line
        with open(config_file, 'r') as fh:
            for line in fh.readlines():

                # Comment or no variable being set? Move on
                if line.startswith('#') or '=' not in line:
                    continue

                # Collect and strip the config bits
                key, val = line.split('=', 1)
                key = key.strip().lower()
                val = val.strip(' "\'\t\r\n')

                # Convert some things as needed booleans and ints
                if val.lower() == 'true':
                    val = True
                elif val.lower() == 'false':
                    val = False
                else:
                    try:
                        val = int(val)
                    except ValueError:
                        pass

                # Save the key-value pair to the config
                self._config[key] = val

        # Debug log the config
        log.debug(f'After loading configuration from: {config_file}')
        for key, val in self.items():
            log.debug(f'  Key: {key}\tValue: {val}')

        log.debug(f'Exiting: Config.load({config_file})')

    def validate(self):
        '''
        Attempt to validate the config
        Also populate defaults that was only want to setup
        if not in config (e.g. temp path)
        '''

        log.debug('Entering: Config.validate()')

        # Helper to cleanup and de-dupe list settings
        def list_from_str(some_str):
            out_list = []
            for thing in some_str.split(','):
                thing = thing.strip()
                if thing and thing not in out_list:
                    out_list.append(thing)
            return out_list

        # Non-critical checks

        # Setup the temp path if not set (not a failure)
        if not self.defined('temp_path'):
            self.temp_path = gettempdir()

        # If additional local_rules are not set, default to empty list
        # Otherwise create a list from the value
        if not self.defined('local_rules'):
            self.local_rules = []
        else:
            self.local_rules = list_from_str(self.local_rules)

        # If ignored files is not set, default to empty list
        # Otherwise create a list from the value
        # NOTE: Also rename this from the config "ignore" to "ignored_files"
        #   (backward-compatible setting name from Perl PulledPork config)
        # If both settings exist, combine, de-dupe, and move to just "ignored_files"
        ignored_files = []
        if self.defined('ignore'):
            ignored_files += list_from_str(self.ignore)
            _ = self._config.pop('ignore')
        if self.defined('ignored_files'):
            ignored_files += list_from_str(self.ignored_files)
        self.ignored_files = list(set(ignored_files))

        # If additional blocklists are not set, default to empty list
        # Otherwise create a list from the value
        if not self.defined('blocklist_urls'):
            self.blocklist_urls = []
        else:
            self.blocklist_urls = list_from_str(self.blocklist_urls)

        # Critical checks below

        # Missing rule path?
        if not self.defined('rule_path'):
            log.error('Required `rule_path` is missing in configuration')

        # Unexpected oinkcode setting?
        if self.defined('oinkcode') and len(self.oinkcode) != 40:
            log.warning('`oinkcode` is not the expected format in configuration')

        # Rule mode unset?
        if not self.defined('rule_mode'):
            log.error('Required `rule_mode` is missing in configuration')

        # Lower the rule mode amd ips_policy
        self.rule_mode = self.rule_mode.lower()
        self.ips_policy = self.ips_policy.lower()

        # Rule mode invalid?
        if self.rule_mode not in ('simple', 'policy'):
            log.error(f'`rule_mode` has an unexpected value: {self.rule_mode}')

        # Using policy rule mode...
        if self.rule_mode == 'policy':

            # No policy_path?
            if not self.defined('policy_path'):
                log.error('`rule_mode` is set to "policy", but `policy_path` is missing in configuration')

            # Invalid IPS policy?
            if self.ips_policy not in VALID_IPS_POLICIES:
                log.error(f'`ips_policy` has an unexpected policy name: {self.ips_policy}')

        # Enabled more than one official ruleset?
        num_enabled_rulesets = [self.community_ruleset, self.registered_ruleset, self.lightspd_ruleset].count(True)
        if num_enabled_rulesets > 1:
            log.warning('More than one official ruleset is selected; not recommended since there is a lot of overlap')

        # Increment the enabled count if we have local rules enabled
        if self.defined('local_rules'):
            num_enabled_rulesets += 1

        # No rulesets enabled?
        if num_enabled_rulesets == 0:
            log.error('No rulesets have been enabled; rule processing cannot continue')

        # Check for enabled rulesets that require an oinkcode
        if any([self.registered_ruleset, self.lightspd_ruleset]) and not self.defined('oinkcode'):
            log.error('`oinkcode` is required when registered or LightSPD rulesets are enabled')

        # Have blocklists enabled, but no target file?
        if any([self.snort_blocklist, self.et_blocklist, len(self.blocklist_urls)]) and not self.defined('blocklist_path'):
            log.error('One or more blocklists are enabled but `blocklist_path` is missing in configuration')

        # Do we need to ensure distro is set in config?

        log.debug('Exiting: Config.validate()')
