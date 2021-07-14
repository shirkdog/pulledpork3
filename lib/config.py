from time import strftime, localtime


class Config(object):
    '''
    Before doing any of the hard work, this is sufficient to
    start the concept of the class
    '''

    start_time     = strftime('%Y.%m.%d-%H.%M.%S', localtime())  # noqa

    tempdir        = ''        # path to our temp working directory  # noqa
    delete_tempdir = True      # should the tempdir be deleted on exit

    args           = ''        # command-line arguments from argparse  # noqa
    config         = ''        # config file values, parsed by ConfigParser  # noqa

    halt_on_warn   = True      # terminate on warning  # noqa

    snort_version  = ''                # snort version (from config or determined programmatically)  # noqa
    ips_policy     = 'connectivity'    # what rules should be enabled/disabled by policy  # noqa
    distro         = None              # distro needed for precompiled so rules  # noqa
    rules_outfile  = ''                # where to write combined rules file  # noqa
    include_disabled_rules = False     # should disabled rules be included in output
    process_so_rules = False           # are we processing so rules
    sorule_path    = ''                # where to copy so rules  # noqa
    ignore_rules_files = []            # what filenames to ignore in the rulesets

    bocklist_outfile = ''          # where to output our combined blocklist file  # noqa

    oinkcode       = None          # snort oninkcode for downloading rulesets and filtering out of output  # noqa
    print_oinkcode = False         # should the Oinkcode be included in the output (usually no)

    rule_mode      = 'simple'      # 'simple' or 'policy': how should rules be enabled in the output  # noqa
    policy_path    = None          # where to write the policy file if rule_mode is 'policy'  # noqa

    pid_path       = None          # if != none, reload snort from the pid at this file path # noqa


def read_config(filename):
    '''
    Parse the config file line-by-line and return a dict

    Adding this to propose replacing ConfigParser so the
    config can be more like the original PulledPork config
    with no need for config "sections". This is a proposal
    only -- no parsing has changed.

    Example:
    >>> parse_config('etc/pulledpork.conf')
    {'community_ruleset': False, 'registered_ruleset': False,
     'lightspd_ruleset': False, 'oinkcode': 'xxxxx',
     'snort_blocklist': False, 'et_blocklist': False,
     'block_list_path': '/usr/local/etc/lists/default.blocklist',
     'ips_policy': 'balanced', 'rule_mode': 'simple',
     'rule_path': '/usr/local/etc/rules/pulledpork.rules',
     'local_rules': '/usr/local/etc/rules/local.rules',
     'include_disabled_rules': False, 'process_so_rules': True,
     'sorule_path': '/usr/local/etc/so_rules/',
     'distro': 'ubuntu-x64', 'configuration_number': '3.0.0-BETA'}
    '''

    # The resulting config
    res = {}

    # Open the config and work through it line-by-line
    with open(filename, 'r') as fh:
        for line in fh.readlines():

            # Comment or no variable being set? Move on
            if line.startswith('#') or '=' not in line:
                continue

            # Collect and strip the config bits
            key, val = line.split('=', 1)
            key = key.strip().lower()
            val = val.strip(' "\'\r\n')

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
            res[key] = val

    # Return the result
    return res
