from time import strftime, localtime


class Config(object):
    '''
    Before doing any of the hard work, this is sufficient to
    start the concept of the class
    '''

    start_time     = strftime('%Y.%m.%d-%H.%M.%S' , localtime())  # noqa

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
