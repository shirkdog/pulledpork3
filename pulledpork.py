#!/usr/bin/env python3
'''
pulledpork3 v(whatever it says below!)

Copyright (C) 2021 Noah Dietrich, Michael Shirk and the PulledPork Team!

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''

from argparse import ArgumentParser         # command line parameters parser
from configparser import ConfigParser       # to parse the conf file
from json import load                       # to load json manifest file in lightSPD
from os import environ, listdir, scandir, mkdir
from os.path import isfile, join, sep, abspath, basename, isdir
from platform import platform, version, uname, system, python_version, architecture
from re import search, sub, match
from shutil import rmtree, copy             # remove directory tree, python 3.4+
from subprocess import Popen, PIPE          # to get Snort version from binary
from sys import exit, argv                  # print argv and  sys.exit
from tarfile import open as open_tar        # to extract tgz ruleset file
from tempfile import gettempdir             # temp directory mgmt
from urllib.parse import urlsplit           # get filename from url

# Third-party libraries
import requests

# Our PulledPork3 internal libraries
from lib import config, logger


# -----------------------------------------------------------------------------
#   GLOBAL CONSTANTS
# -----------------------------------------------------------------------------

__version__ = '3.0.0-BETA'

SCRIPT_NAME = 'PulledPork'
TAGLINE = 'Lowcountry yellow mustard bbq sauce is the best bbq sauce. Fight me.'
VERSION_STR = f'{SCRIPT_NAME} v{__version__}'

# URLs for supported rulesets (replace <version> and <oinkcode> when downloading)
RULESET_URL_SNORT_COMMUNITY = 'https://snort.org/downloads/community/snort3-community-rules.tar.gz'
RULESET_URL_SNORT_REGISTERED = 'https://snort.org/rules/snortrules-snapshot-<VERSION>.tar.gz?oinkcode=<OINKCODE>'
RULESET_URL_SNORT_LIGHTSPD = 'https://snort.org/rules/Talos_LightSPD.tar.gz?oinkcode=<OINKCODE>'

# TODO: Support for the ET Rulesets has not yet been implemented
# RULESET_URL_ET_OPEN = 'https://rules.emergingthreats.net/open/snort-<VERSION>/emerging.rules.tar.gz'
# RULESET_URL_ET_PRO = 'https://rules.emergingthreatspro.com/<ET_OINKCODE>/snort-<VERSION>/etpro.rules.tar.gz'

# URLs for supported blocklists
SNORT_BLOCKLIST_URL = 'https://snort.org/downloads/ip-block-list'
ET_BLOCKLIST_URL = 'http://rules.emergingthreatspro.com/fwrules/emerging-Block-IPs.txt'


# -----------------------------------------------------------------------------
#   Prepare the logging and config
# -----------------------------------------------------------------------------

log = logger.Logger()
gc = config.Config()


# -----------------------------------------------------------------------------
#   MAIN FUNCTION - program execution starts here.
# -----------------------------------------------------------------------------

def main():

    # parse our command-line args with ArgParse
    gc.args = parse_argv()

    # if the -V flag (version) was passed: Print the script Version and Exit
    if gc.args.version:
        print(VERSION_STR)
        exit(0)

    # Always show pigs flying as the preamble, regardless of verbosity
    flying_pig_banner()

    # Setup logging as requested
    #   NOTE: For now all the args are permitted, but specifying more than one
    #         will override less verbose ones. Priority order:
    #               DEFAULT (info) < quiet < verbose < debug
    if gc.args.quiet:
        log.level = logger.Levels.WARNING
    if gc.args.verbose:
        log.level = logger.Levels.VERBOSE
    if gc.args.debug:
        log.level = logger.Levels.DEBUG
        print_environment(gc)

    # Also setup halt on warn as requested
    log.halt_on_warn = not gc.args.ignore_warn

    # Load the configuration File from command line (-c FILENAME). Verify exists, and only 1 entry.
    if not gc.args.configuration:
        log.error("The following arguments are required: -c/--configuration <file>")
    if len(gc.args.configuration) > 1:
        log.warning('Multiple entries passed as -c/--configuration.  Only a single entry permitted.')

    config_file = gc.args.configuration[0]  # this is a list of one element
    log.info('Loading configuration file: ' + config_file)

    # load configuration file into config variable with ConfigParser
    gc.config = ConfigParser(delimiters=('='))
    try:
        gc.config.read_file(open(config_file, "r"))
    except Exception as e:
        log.error("Can not load required configuration file. Error: " + str(e))

    # if we are given an oinkcode, we must save it to the gc.oinkcode variable
    # so we can filter it out from printed output (in our 'log' function)
    if gc.config.has_option('rulesets', 'oinkcode'):
        gc.oinkcode = gc.config['rulesets']['oinkcode']

    log.debug('After parsing configuration file, the Dictionary returned is:')
    for sect in gc.config.sections():
        log.debug("\tSection: " + sect)
        for k, v in gc.config.items(sect):
            log.debug("\t\tKey: " + k + "\tValue: " + v)

    # Validate configuration file (logical validation of settings; error out if issue)
    #   determine fields for GC from command line and config file, save in global gc
    # todo: join these two functions into single function
    validate_configuration()
    determine_configuration_options()

    # Update logging if we're not printing the oinkcode
    if not gc.print_oinkcode:
        log.add_hidden_string(gc.oinkcode)

    # Create a temp working directory (path stored as a string)
    gc.tempdir = get_temp_directory(gc.start_time)
    log.verbose("Temporary working directory is: " + gc.tempdir)

    # Determine a set of required info, from config file or from the computer itself
    gc.snort_version = get_snort_version()
    gc.distro = get_distro()
    gc.ips_policy = get_policy()

    # we now have all required info to run, print the configuration to screen
    print_operational_settings()

    # Obtain the archived ruleset (tgz) files
    # either from online sources or from a local folder
    local_rulesets = []  # list of full file paths to tgz files (local filenames or the path to the tgz files after download)

    if gc.args.file:
        log.debug("Using one file for ruleset source (not downloading rulesets): " + gc.args.file)
        # determine ruleset type from filename
        if 'snort3-community-rules' in gc.args.file:
            local_rulesets.append(('SNORT_COMMUNITY', gc.args.file))
        elif 'snortrules-snapshot-' in gc.args.file:
            local_rulesets.append(('SNORT_REGISTERED', gc.args.file))
        elif 'Talos_LightSPD' in gc.args.file:
            local_rulesets.append(('SNORT_LIGHTSPD', gc.args.file))
        else:
            local_rulesets.append(('UNKNOWN', gc.args.file))

    elif gc.args.folder:
        log.debug("Using all files for ruleset source (not downloading) from: " + gc.args.folder)
        for path in listdir(gc.args.folder):
            full_path = join(gc.args.folder, path)
            if isfile(full_path) and (full_path.endswith('tar.gz') or (full_path.endswith('tgz'))):
                # determine ruleset type from filename
                if 'snort3-community-rules' in full_path:
                    local_rulesets.append(('SNORT_COMMUNITY', full_path))
                elif 'snortrules-snapshot-' in full_path:
                    local_rulesets.append(('SNORT_REGISTERED', full_path))
                elif 'Talos_LightSPD' in full_path:
                    local_rulesets.append(('SNORT_LIGHTSPD', full_path))
                else:
                    local_rulesets.append(('UNKNOWN', full_path))
    else:
        # create list of ruleset URLS from the various RULESETs provided
        ruleset_urls = determine_ruleset_urls()

        # Download rulesets to temp directory
        # local_rulesets.append( download_rulesets(ruleset_urls) )
        local_rulesets = download_rulesets(ruleset_urls)

    # extract rulesets to folder (tupple with ID, full path of folders for extracted rulesets)
    extracted_rulesets = untar_rulesets(local_rulesets)

    if not extracted_rulesets:
        log.warning("No Extracted Ruleset folders found.")

    # PROCESS RULESETS HERE
    # extracted_rulesets is a list of tuples. Each tuple represents a folder in the temp directory
    #  that contains a ruleset.
    # the tuple is made up of an ID and the full path to the ruleset folder
    # the ID is a known entity (SNORT_COMMUNITY..., or the identifier from the config file for the url)
    # this ID is used later for post-rule processing.

    all_rules = []               # list of all text rules found, each entry is a rule (dict)
    # other_policies = []         # todo: if policies_path is set (write other policies files)

    for rule_set in extracted_rulesets:
        log.debug('---------------------------------')
        log.debug("Working on Ruleset: " + rule_set[0] + ' - ' + rule_set[1])

        # determine ruleset type:
        if rule_set[0] == 'SNORT_COMMUNITY':
            # only simple rules to worry about
            r = get_text_rules_from_folder(rule_set[1], 'SNORT_COMMUNITY', rule_set[0], 'text')

            # We need to create policies regardless of output
            for rule in r:
                s = is_rule(rule['rule'])
                if s:
                    rule['enabled'] = s['enabled']
                    rule['rule'] = s['rule']

            all_rules.extend(r)
            log.verbose(str(len(r)) + ' actual rules found in Community ruleset')

        elif rule_set[0] == 'SNORT_REGISTERED':

            # process text rules
            text_rules_path = str(rule_set[1] + sep + 'rules')
            rules = get_text_rules_from_folder(text_rules_path, 'SNORT_REGISTERED', 'snort_ruleset', 'text')
            pol = get_policy_from_file(text_rules_path + sep + gc.ips_policy)

            # process builtin rules
            builtin_rules_path = str(rule_set[1] + sep + 'builtins')
            r = get_text_rules_from_folder(builtin_rules_path, 'SNORT_REGISTERED', 'snort_ruleset', 'builtin')
            rules.extend(r)
            p = get_policy_from_file(builtin_rules_path + sep + gc.ips_policy)
            pol.extend(p)

            # process policies
            # we need policies even if we're in simple mode
            # pol =  get_policy_from_file(rule_set[1] + sep + 'rules' + sep + gc.ips_policy )

            # process so rules
            if gc.process_so_rules:
                # copy files first to temp\so_rules folder (we'll copy them all at the end, this checks for dupes)
                # todo: error handling
                so_src_folder = rule_set[1] + sep + 'so_rules' + sep + 'precompiled' + sep + gc.distro + sep
                src_files = listdir(so_src_folder)
                for file_name in src_files:
                    full_file_name = join(so_src_folder, file_name)
                    if isfile(full_file_name):
                        copy(full_file_name, gc.tempdir + sep + 'so_rules' + sep)

                # get SO rule stubs
                # todo: generate stubs if distro folder doesn't exist
                so_rules_path = str(rule_set[1] + sep + 'so_rules')
                r = get_text_rules_from_folder(so_rules_path, 'SNORT_REGISTERED', 'snort_ruleset', 'so')
                rules.extend(r)

                # Get So rule policies
                p = get_policy_from_file(rule_set[1] + sep + 'so_rules' + sep + gc.ips_policy)
                pol.extend(p)

            # we need to use the policy (.states) file to mark rules as enabled/disabled

            # create list of fingerprints for all enabled policies
            enabled_rule_policies = []
            for state in pol:
                gid = search(r'gid:(\d+);', state)
                sid = search(r'sid:(\d+);', state)
                action = search(r'; enable;\)$', state)

                if sid and gid and action:
                    gid = gid.group(1)
                    sid = sid.group(1)
                    # this is a valid enable policy
                    # any rules matching this policy entry should be enabled
                    enabled_rule_policies.append(gid + ':' + sid + ':')

            for r in rules:
                if r['fingerprint']:
                    # fingerprints are slightly different between policy file and rule file (policy has no REV)
                    fgr = search(r'^(\d+:\d+:)\d$', r['fingerprint'])

                    if fgr and fgr.group(1) in enabled_rule_policies:
                        r['enabled'] = True
                    else:
                        r['enabled'] = False

            all_rules.extend(rules)

        elif rule_set[0] == 'SNORT_LIGHTSPD':

            rules = []
            pol = []

            # the manifest.json file is only used (at this time) for processing .so rules
            if gc.process_so_rules:

                json_manifest_file = rule_set[1] + sep + 'lightspd' + sep + 'manifest.json'

                # load json manfiest file to identify .so rules location
                log.verbose('Processing json manifest file ' + json_manifest_file)
                with open(json_manifest_file) as f:
                    manifest = load(f)

                manifest_versions = []
                for i in manifest["snort versions"]:
                    manifest_versions.append(i)

                manifest_versions = sorted(manifest_versions, reverse=True)

                log.debug('Found ' + str(len(manifest_versions)) + ' versions of snort in the manifest file: ' + str(manifest_versions))

                # find version number in the json file that is the largest number just below or equal to the version of snort3.
                log.debug('Looking for a version in the manifest file that is less than or equal to our current snort Version: ' + gc.snort_version)
                version_to_use = None
                for v in manifest_versions:
                    if v <= gc.snort_version:
                        version_to_use = v
                        break

                if version_to_use is None:
                    log.warning("Not able to find a valid snort version in the lightSPD manifest file. not processing any SO rules from the lightSPD package.")
                else:
                    log.debug("Using snort version " + version_to_use + ' from lightSPD manifest file. Actual Snort version is: ' + gc.snort_version)
                    # get other data from manifest file for the selected version
                    policies_path = manifest["snort versions"][version_to_use]['policies_path']
                    policies_path = policies_path.replace('/', sep)
                    log.debug('policies_path from lightSPD Manifest file for snort ' + version_to_use + ' is: ' + policies_path)

                    # todo: try/catch next line in case the arch. doesn't exist
                    modules_path = manifest["snort versions"][version_to_use]['architectures'][gc.distro]["modules_path"]
                    modules_path = modules_path.replace('/', sep)
                    log.debug('modules_path from lightSPD Manifest file for snort ' + version_to_use + ' is: ' + modules_path)

                    # copy so files from our archive to working folder
                    so_src_folder = rule_set[1] + 'lightspd' + sep + modules_path + sep + 'so_rules' + sep
                    src_files = listdir(so_src_folder)
                    for file_name in src_files:
                        full_file_name = join(so_src_folder, file_name)
                        if isfile(full_file_name):
                            copy(full_file_name, gc.tempdir + sep + 'so_rules' + sep)

                    # get SO rule stub files
                    # todo: generate stubs if distro folder doesn't exist
                    so_rules_path = rule_set[1] + 'lightspd' + sep + 'modules' + sep + 'stubs' + sep
                    r = get_text_rules_from_folder(so_rules_path, 'SNORT_LIGHTSPD', 'snort_ruleset', 'so')
                    rules.extend(r)

                    # Get So rule policies
                    p = get_policy_from_file(so_rules_path + sep + gc.ips_policy)
                    pol.extend(p)

                log.debug("Completed loading lightSPD Ruleset .so rules. " + str(len(r)) + ' rules found')

            # LOAD TEXT RULES FROM LightSPD archive
            # right now, the LightSPD archive only has a 3.0.0.0 folder in it, so let's use that explicitly.
            # this should hopefully be changed to an explicit entry in the manifest.json file

            text_rules_path = rule_set[1] + sep + 'lightspd' + sep + 'rules' + sep + '3.0.0.0' + sep

            r = get_text_rules_from_folder(text_rules_path, 'SNORT_LIGHTSPD', 'snort_ruleset', 'text')
            p = get_policy_from_file(text_rules_path + sep + gc.ips_policy)

            log.debug("Completed loading lightSPD Ruleset text rules. " + str(len(r)) + ' rules found')
            rules.extend(r)
            pol.extend(p)

            # LOAD BULTIN RULES FROM LightSPD archive
            # right now, the LightSPD folder has a single 3.0.1-3 folder in it, so let's use that explictly
            # hopefully this will be changed to an explicit entry in the manifest.json file
            builtin_rules_path = str(rule_set[1] + sep + 'lightspd' + sep + 'builtins' + sep + '3.0.0-264')
            r = get_text_rules_from_folder(builtin_rules_path, 'SNORT_LIGHTSPD', 'snort_ruleset', 'builtin')
            p = get_policy_from_file(builtin_rules_path + sep + gc.ips_policy)

            log.debug("Completed loading lightSPD Ruleset builtin rules. " + str(len(r)) + ' rules found')
            rules.extend(r)
            pol.extend(p)

            # due to the way lightSPD uses .states files (policies) to enable and disabled individual rules, we need to
            # determine which rules are enabled and disabled by checking the GID:SID for each rule against all the
            # entries in the policy file. We fingerprint each rule (GID:SID) and compare it against all the policys listed.
            # the state (enabled/disabled) is written as another entry in each rules dictionary (the 'enabled' entry).
            # create fingerprints of rules
            enabled_rule_policies = []
            for state in pol:
                gid = search(r'gid:(\d+);', state)
                sid = search(r'sid:(\d+);', state)
                action = search(r'; enable;\)$', state)

                if sid and gid and action:
                    gid = gid.group(1)
                    sid = sid.group(1)
                    # this is a valid enable policy
                    # any rules matching this policy entry should be enabled
                    enabled_rule_policies.append(gid + ':' + sid + ':')

            # Mark rule object (enabled dict entry) as enabled or disabled based on the policy file
            for r in rules:
                if r['fingerprint']:
                    # fingerprints are slightly different between policy file and rule file (policy has no REV)
                    fgr = search(r'^(\d+:\d+:)\d$', r['fingerprint'])

                    if fgr and fgr.group(1) in enabled_rule_policies:
                        r['enabled'] = True
                    else:
                        r['enabled'] = False

            # last step for LightSPD rules, save back with all the other rules
            all_rules.extend(rules)

        else:
            log.warning("Unknown ruleset archive folder recieved.")
            # TODO: non-standard ruleset, we need to figure it out

    # all_rules = [] # list of rule_dicts. each entry is a individual rule with associated metadata.
    #  rule_dict = {
    #       uid            =  Unique Identifier (from the conf file)
    #       ruleset_type   =  the format of ruleset, MUST be: (snort_lightspd, snort_community, snort_ruleset, other)
    #       rule           =  the actual rule, in text format (alert any any....), no comments
    #       filename       =  the filename where the rule came from ('server-iss.rules' for example)
    #       source_type    =  the source of the rule, MUST be: (text, builtin, so, local)
    #       enabled         = boolean - if the rule is enabled based on policy (registered) or commented out (community)
    #  }

    log.debug("There are " + str(len(all_rules)) + ' rules after downloading and processing all rulesets.')

    # load any local.rules and add to rules list
    local_rules = load_local_rules()

    all_rules.extend(local_rules)
    log.debug("There are " + str(len(all_rules)) + ' rules after loading local rules files.')

    # modify rules based on LARK (todo)
    # Convert rules from string to dict (todo: can we keep this as a parse tree and work on it?)
    '''
    rules = objectify_rules(rules)
    log.debug("There are " + str(len(rules)) + ' rules (dict) after converting rule strings to dicts.' )

    -----------------------------------------------------------------------------
    Post-process rules (todo) -> create DSL and parse this way
    de-dupe rules(? is this needed)
    enable/disable rules
    modify rules
    flowbit fixing

    test example: enable ALL Rules.
    this is how i'll apply a DSL to the rules for enable/disable (or operate on parse tree)
    for rule in rules:
       rule['enabled'] = True
    log.debug("We have " + str(len(rules)) + ' enabled rule objects.' )

    Remove disabled rules from output if requested by user.
    if not gc.include_disabled_rules:
       log.verbose("Removing disabled rules from output.")
       rules = list(filter(lambda d: d['enabled'], rules))
       log.debug("There are " + str(len(rules)) + ' rules after removing disabled rules.' )

    convert rules from dict back to string
    rules = stringify_rules(all_rules)
    log.debug("There are " + str(len(rules)) + ' rules (string) after converting rules from dict to string.' )
    '''

    # Prepare rules for output

    # remove disabled rules if not including them in the output
    if not gc.include_disabled_rules:
        log.debug("Removing disabled rules from output")
        all_rules = [r for r in all_rules if r['enabled']]

    #   OUTPUT

    write_rulesets_to_disk(all_rules, gc.rules_outfile)

    # write the policy to disk
    if gc.rule_mode == 'policy':
        # parse all rules for enabled rules, and build policy file from that
        all_states = []
        for rule in all_rules:
            if rule['enabled']:
                action = rule['rule'].split()[0]
                g, s, _ = rule['fingerprint'].split(':', 2)
                all_states.append(action + '(gid:' + g + '; sid: ' + s + '; enable;)' + "\n")

        write_state_to_disk(all_states, gc.policy_path)

    # copy .so rules from tempdir
    # todo: delete old rules
    if gc.process_so_rules:
        so_src_folder = gc.tempdir + sep + 'so_rules' + sep
        src_files = listdir(so_src_folder)
        for file_name in src_files:
            full_file_name = join(so_src_folder, file_name)
            if isfile(full_file_name):
                copy(full_file_name, gc.sorule_path)

    # -----------------------------------------------------------------------------
    # Download Blocklists
    log.info("Preparing to process blocklists.")
    bloclist_urls = get_blocklist_urls()
    blocklist_entries = get_blocklists(gc.start_time, bloclist_urls)

    write_blocklists_to_file(blocklist_entries)

    # todo:  Reload snort (sighup)

    # unix/linux SIGHUP
    # import os, signal
    # os.kill(pid, signal.SIGHUP)

    # windows SIGHUP
    # import ctypes
    # ucrtbase = ctypes.CDLL('ucrtbase')
    # c_raise = ucrtbase['raise']
    # c_raise(some_signal)

    # -----------------------------------------------------------------------------
    # Delete temp dir
    if not gc.delete_tempdir:
        log.verbose("Not deleting temporary working directory: " + gc.tempdir)
    else:
        log.verbose("Attempting to delete temporary working directory: " + gc.tempdir)
        try:
            rmtree(gc.tempdir)
        except OSError as e:
            log.warning("Warning: Can't delete temporary working directory: " + e.filename + '.  Error is: ' + e.strerror)
        else:
            log.verbose("Successfully deleted temporary working directory: " + gc.tempdir)

    # -----------------------------------------------------------------------------
    # END Program Execution (main function)
    log.info('Program execution complete.')

# *****************************************************************************
# *****************************************************************************
#
#
#                       END OF MAIN FUNCTION
#
#
# *****************************************************************************
# *****************************************************************************


def flying_pig_banner():
    '''
    OMG We MUST HAVE FLYING PIGS! The community demands it.
    '''

    # For now simple printing, will need to clean this up
    print(f"""
    https://github.com/shirkdog/pulledpork3
      _____ ____
     `----,\\    )
      `--==\\\\  /    {VERSION_STR} - {TAGLINE}
       `--==\\\\/
     .-~~~~-.Y|\\\\_  Copyright (C) 2021 Noah Dietrich, Michael Shirk
  @_/        /  66\\_  and the PulledPork Team!
    |    \\   \\   _(\")
     \\   /-| ||'--'  Rules give me wings!
      \\_\\  \\_\\\\
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~""")


def parse_argv():
    '''
    Get command line arguments into global argparser variable
    '''

    # Parse command-line arguments
    arg_parser = ArgumentParser(description=f'{VERSION_STR} - {TAGLINE}')

    # we want Quiet or Verbose (v, vv), can't have more than one (but we can have none)
    group_verbosity = arg_parser.add_mutually_exclusive_group()
    group_verbosity.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
    group_verbosity.add_argument("-vv", "--debug", help="Really increase output verbosity", action="store_true")
    group_verbosity.add_argument("-q", "--quiet", help='Only display warnings and errors', action="store_true")

    # input file or folder (optional)
    group_input = arg_parser.add_mutually_exclusive_group()
    group_input.add_argument("-f", "--file", help="Use this file as source of rulesets", type=abspath)
    group_input.add_argument("-F", "--folder", help="Use all the tgz file in this folder as source of rulesets", type=abspath)

    # standard arguments
    arg_parser.add_argument("-c", "--configuration", help="path to the configuration file", nargs=1, type=abspath)
    arg_parser.add_argument("-V", "--version", help='Print version number and exit', action="store_true")
    arg_parser.add_argument("-k", "--keep-temp-dir", help='Do not delete the temp directory when done', action="store_true")
    arg_parser.add_argument("-po", "--print-oinkcode", help='Do not obfuscate oinkcode in output.', action="store_true")
    arg_parser.add_argument("-i", "--ignore-warn", help='Ignore warnings and continue processing.', action="store_true")

    return arg_parser.parse_args()


def validate_configuration():
    '''
    Validate the command line params and the config file (-c <file>)
    also determine the flags and params here
    '''

    log.verbose("Validating input configuration file settings.")

    # Validate Section: CONFIGURATION
    # required: [configuration]rule_path -> where to save combined rules file
    if not gc.config.has_option('configuration', 'rule_path'):
        log.error("Required rule_path in [configuration] section is missing.")

    # is our oinkcode valid format?
    if gc.oinkcode is not None and len(gc.oinkcode) != 40:
        log.warning("Oinkcode does not seem to be the correct format.")

    # do we know how to write enabled rules?
    if gc.config.has_option('configuration', 'rule_mode'):
        if gc.config['configuration']['rule_mode'] != 'simple' and gc.config['configuration']['rule_mode'] != 'policy':
            log.error('"rule_mode" is not set or is an invalid value. value is: ' + gc.config['configuration']['rule_mode'])

    # if rule_mode == policy, do we have an output path
    if gc.config['configuration']['rule_mode'] == 'policy' and not gc.config.has_option('configuration', 'policy_path'):
        log.error('"policy_path" is not set. this is required when rule_mode is "policy".')

    # Validate Section: RULESETS

    # are we getting rulesets from local file (command line) or from online (config file)
    if gc.args.file or gc.args.folder:
        log.verbose("Rulesets will be loaded from local system, not online sources.")

        # valide command line args (other than ones checked by argparser)
        if gc.args.file and not isfile(gc.args.file):
            log.error("File path passed by -f is not a file or does not exist: " + gc.args.file)

        if gc.args.folder:
            if not isdir(gc.args.folder):
                log.error("Folder path passed by -F is not a folder or does not exist: " + gc.args.folder)
            if not listdir(gc.args.folder):
                log.error("Folder path passed by -F contains no files.")
    else:
        log.debug("Rulesets will be downloaded from online sources (not the local filesystem).")

        # We are not using local rulesets, so we need online rulesets (note, user might only want blocklists,
        # so this is a warning that can be overridden.)
        if not gc.config.has_section('rulesets'):
            log.warning("Missing section [rulesets] in configuration file.  No rulesets can be downloaded")

        # log warning if downloading multiple snort rulesets (only 1 recommended)
        if [gc.config['rulesets'].getboolean('registered_ruleset'),
            gc.config['rulesets'].getboolean('LightSPD_ruleset'),
            gc.config['rulesets'].getboolean('community_ruleset')].count(True) > 1:
            log.warning("You have specified more than one Ruleset from Snort/Talos. This is not recommended (community, registered, and LightSPD have a lot of overlap).")

        # make sure we are getting rules from somewhere (local.rules, snort ruleset, or URL(todo))
        if not any([gc.config['rulesets'].getboolean('registered_ruleset'),
                    gc.config['rulesets'].getboolean('LightSPD_ruleset'),
                    gc.config['rulesets'].getboolean('community_ruleset'),
                    gc.config.has_option('configuration', 'local_rules')]):
            log.warning("No rulesets have been specified for download. Rule Processing won't happen.")

        # if we are downloading the registered or lightSPD ruleset, we also require a oinkcode
        if gc.config['rulesets'].getboolean('registered_ruleset') or gc.config['rulesets'].getboolean('LightSPD_ruleset'):
            if not gc.config.has_option('rulesets', 'oinkcode'):
                log.error("Oinkcode is requred for the registered or LightSPD rulesets. These will not be downloaded.")

        # todo: ET RULESETS

        # todo: if process_so_rules

    # blocklist validation
    # TODO: if we have blocklists to download, we require block_list_path
    # TODO: extra blocklists
    # TODO; if we havea block_list_path but no URLS, warn
    # TODO: test if [blocklist] does not exist
    if any([gc.config['blocklist'].getboolean('snort_blocklist'),
            gc.config['blocklist'].getboolean('et_blocklist')]) and gc.bocklist_outfile is None:
        log.error("No block_list_path specified in configuration. This is required if you are downloading blocklists.")

    log.verbose("Done Validating input configuration file settings. No fatal errors.")


def determine_configuration_options():
    '''
    Combine the command line params and the config file (-c <file>)
      save back to global gc
    todo: use .lower() on all options
    todo: remove quotes from file paths
    '''

    log.debug("Entering Function determine_configuration_options()")

    # do we print the oinkcode in the output
    gc.print_oinkcode = gc.args.print_oinkcode

    # Do we delete temp directory on exit
    gc.delete_tempdir = not gc.args.keep_temp_dir

    # where to write the snort rules (snort.rules)
    gc.rules_outfile = gc.config['configuration']['rule_path']

    # do we include disabled rules in the output?
    if gc.config.has_option('configuration', 'include_disabled_rules'):
        gc.include_disabled_rules = gc.config['configuration'].getboolean('include_disabled_rules')

    # what is our rule_policy (write simple rules, or use a policy file)
    if gc.config.has_option('configuration', 'rule_mode'):
        gc.rule_mode = gc.config['configuration']['rule_mode'].lower()

    # if we are in policy mode, we need to get the path to write the policy
    if gc.rule_mode == 'policy':
        if gc.config.has_option('configuration', 'policy_path'):
            gc.policy_path = gc.config['configuration']['policy_path'].lower()
        else:
            log.error('"policy_path" not specified, but is required when "rule_mode" is "policy".')

    # are we processing SO rules?
    if gc.config.has_option('configuration', 'process_so_rules'):
        gc.process_so_rules = gc.config['configuration'].getboolean('process_so_rules')

        if gc.config.has_option('configuration', 'sorule_path'):
            gc.sorule_path = gc.config['configuration']['sorule_path']
        else:
            log.error('"sorule_path" is required when "process_so_rules" is set to "true".')

    # get list of filenames to ignore in a ruleset
    if gc.config.has_option('rulesets', 'ignore_files'):
        r = gc.config['rulesets']['ignore_files']
        if r:
            gc.ignore_rules_files = [x.strip() + '.rules' for x in r.split(',')]

    # where to write the blockfile
    # todo: this may not exist if not processing blocklists
    gc.bocklist_outfile = gc.config['blocklist']['block_list_path']

    log.debug("Exiting Function determine_configuration_options()")


def print_operational_settings():
    '''
    Print all the operational settings after parsing (what we will do)
    '''

    log.verbose('------------------------------------------------------------')
    log.verbose("After parsing the command line and configuration file, this is what I know:")

    # halt-on-error
    if gc.halt_on_warn:
        log.verbose('Program will terminate when encountering an error or warning.')
    else:
        log.verbose('Warnings will not cause this program to terminate (damn the torpedos, full speed ahead!).')

    # are we printing oinkcode?
    if gc.print_oinkcode:
        log.verbose('Oinkcode will NOT be obfuscated in the output (do not share your oinkcode).')
    else:
        log.verbose('Oinkcode will be obfuscated in the output (this is a good thing).')

    # Temp dir management
    log.verbose('Temporary working directory is: ' + gc.tempdir)

    if gc.delete_tempdir:
        log.verbose('Temporary working directory will be deleted at the end.')
    else:
        log.verbose('Temporary working directory will not be deleted at the end.')

    # env. variables
    log.verbose('The Snort version number used for processing is: ' + gc.snort_version)
    if gc.distro:
        log.verbose('The distro used for processing is: ' + gc.distro)
    log.verbose('The ips policy used for processing is: ' + gc.ips_policy)

    if gc.process_so_rules:
        log.verbose('Pre-compiled (.so) rules will be processed.')
        log.verbose('Pre-compiled (.so) files will be saved to: ' + gc.sorule_path)
    else:
        log.verbose('Pre-compiled (.so) rules will not be processed.')
    # ruelset locations
    if gc.args.file:
        log.verbose('Rulesets will not be downloaded, they will be loaded from a single local file: ' + "\n\t" + gc.args.file)
    elif gc.args.folder:
        log.verbose('Rulesets will not be downloaded, they will be loaded from all files in local folder: ' + "\n\t" + gc.args.folder)
    else:
        log.verbose('Rulesets will be downloaded from: ')
        if gc.config['rulesets'].getboolean('registered_ruleset'):
            log.verbose("\tSnort Registered Ruleset")
        if gc.config['rulesets'].getboolean('community_ruleset'):
            log.verbose("\tSnort Community Ruleset")
        if gc.config['rulesets'].getboolean('LightSPD_ruleset'):
            log.verbose("\tSnort LightSPD Ruleset")

    #   Rules
    if gc.ignore_rules_files:
        log.verbose('The following rules files will not be included in rulesets: ' + str(gc.ignore_rules_files))

    log.verbose("Rule Output mode is: " + gc.rule_mode)
    if gc.rule_mode == 'policy':
        log.verbose('Policy file to write is: ' + gc.policy_path)

    # local rules files
    for opt in gc.config.options('configuration'):
        if opt.startswith('local_rules'):
            log.verbose('Rules from Local rules file will be included: ' + gc.config['configuration'][opt])

    log.verbose("All Rules will be written to a single file: " + gc.config['configuration']['rule_path'])
    if gc.include_disabled_rules:
        log.verbose("Disabled rules will be written to the rules file")
    else:
        log.verbose("Disabled rules will not be written to the rules file")

    # policys
    log.verbose('The rule_mode is: ' + gc.rule_mode)
    if gc.rule_mode == 'policy':
        log.verbose('the policy file written (to specify enabled rules) is: ' + gc.policy_path)

    # blocklists
    if gc.config['blocklist'].getboolean('snort_blocklist'):
        log.verbose("Snort blocklist will be downloaded")
    if gc.config['blocklist'].getboolean('et_blocklist'):
        log.verbose("ET blocklist will be downloaded")
    other_bl = False
    for bl in gc.config.options('blocklist'):
        if bl.startswith('blocklist_'):
            log.verbose("Other blocklist will be downloaded: " + gc.config['blocklist'][bl])
            other_bl = True

    if not any([gc.config['blocklist'].getboolean('snort_blocklist'),
                gc.config['blocklist'].getboolean('et_blocklist')]) and not other_bl:
        log.verbose("No Blocklists will be downloaded.")
    else:
        log.verbose('Blocklist entries will be written to: ' + gc.config['blocklist']['block_list_path'])

    log.verbose('------------------------------------------------------------')


def determine_ruleset_urls():
    '''
    return a list of full URLs to download rulesets (TGZ) from
    in: nothing (pulls info from global config )
    out: list of entries, each entry is a tuple (source_ID, url)
         source_ID is to tell us where we got the entry
    '''

    urls = []

    if gc.config['rulesets'].getboolean('community_ruleset'):
        u = ('SNORT_COMMUNITY', RULESET_URL_SNORT_COMMUNITY)
        urls.append(u)

    if gc.config['rulesets'].getboolean('registered_ruleset'):
        r = RULESET_URL_SNORT_REGISTERED.replace('<OINKCODE>', gc.oinkcode)
        version = sub(r'[^a-zA-Z0-9]', '', gc.snort_version)  # version in URL is alphanumeric only
        r = r.replace('<VERSION>', version)
        u = ('SNORT_REGISTERED', r)
        urls.append(u)

    if gc.config['rulesets'].getboolean('LightSPD_ruleset'):
        r = RULESET_URL_SNORT_LIGHTSPD.replace('<OINKCODE>', gc.oinkcode)
        u = ('SNORT_LIGHTSPD', r)
        urls.append(u)

    # todo: other rulesets by URL

    # todo: ET rulesets

    log.verbose('Returning ' + str(len(urls)) + ' ruleset URLs:')
    for url in urls:
        log.verbose("\t" + url[0] + " - " + url[1])
    return urls


def download_rulesets(urls):
    '''
    Download ruleset archives (tgz) from online
        in: list of tuples, (ID, url)
        out: list of tuples, (id, full path of downloaded tgz files)
    '''

    downloaded_rulesets_dir = gc.tempdir + sep + 'downloaded_rulesets' + sep
    # extracted_rulesets_dir = gc.tempdir + sep + 'extracted_rulesets' +sep

    log.verbose('Preparing to download the following rulesets to temp directory: ' + downloaded_rulesets_dir)
    for u in urls:
        log.verbose("\t" + u[0] + " - " + u[1])

    ruleset_archive_files = []   # array of tuples of ID and full path of downloaded tgz archive rulesets

    # Download and extract rulesets
    # todo: check if empty & warn (not fail)
    # todo: if url doesn't contain filename, dtermine from server
    # https://stackoverflow.com/questions/2795331/python-download-without-supplying-a-filename
    for url in urls:
        log.debug("-----------------------------------------")
        filename = urlsplit(url[1]).path.split("/")[-1]

        log.info('Downloading ruleset file: ' + filename + ' from: ' + url[1])

        r = requests.get(url[1])

        # Retrieve HTTP meta-data
        # print("\t" + r.status_code)
        # print("\t" + r.headers['content-type'])
        # print("\t" + r.encoding)

        log.info('Writing ruleset file to disk: ' + downloaded_rulesets_dir + filename)

        with open(downloaded_rulesets_dir + filename, 'wb') as f:
            f.write(r.content)

        # create list of rulesets
        t = (url[0], downloaded_rulesets_dir + filename)
        ruleset_archive_files.append(t)

    return ruleset_archive_files


def untar_rulesets(files):
    '''
    untar archives to folder,
        in: Tuple, ID,  full file paths of archive files (tgz)
        out: tuple, ID, full path of extracted folders (tgz)
    '''

    extracted_rulesets_dir = gc.tempdir + sep + 'extracted_rulesets' + sep

    folder_names = []   # the list of folder names of extracted tgz files (full path)

    log.verbose("Preparing to extract the following ruleset tarball files to temp directory: \n\t(tempdir) " + extracted_rulesets_dir)

    for f in files:
        log.verbose("\t(ruleset tarball) " + str(f))
        # log.verbose("\t(ruleset tarball) " + f[1])

    for file in files:

        # extract TGZ files
        log.debug('Working on file: ' + file[1])

        filename = basename(file[1])
        # get the filename
        if filename.endswith('.tgz'):
            out_foldername = extracted_rulesets_dir + filename[:-4] + sep
        elif filename.endswith('.tar.gz'):
            out_foldername = extracted_rulesets_dir + filename[:-7] + sep
        else:
            out_foldername = extracted_rulesets_dir + filename + sep

        log.debug("Out_foldername is: " + out_foldername)

        log.verbose('Extracting tgz file: ' + file[1] + " to " + out_foldername)
        # todo: error check: https://docs.python.org/3/library/tarfile.html#tarfile.open
        tgz = open_tar(file[1])
        tgz.extractall(out_foldername)  # specify which folder to extract to
        tgz.close()
        folder_names.append((file[0], out_foldername))

    return folder_names


def get_text_rules_from_folder(rulefolder_path, uid, ruleset_type, source_type):
    '''
    Return text rules sorted by filename from a folder
        in: full path (string) to a folder, ruleset_type (builtin,text,so)
        out: list of dicts:
            rule_dict = {
                 uid         =  Unique Identifier (from the conf file)
                 ruleset_type  =  the format of ruleset, must be: (snort_lightspd, snort_community, snort_ruleset, other)
                 rule        =  the actual rule, in text format
                 filename    =  the filename where the rule came from (server-iss.rules for example)
                 source_type      =  the source of the rule, must be: (text, builtin, so, local)
             }
    '''
    log.debug('In function get_text_rules_from_folder. rulefolder_path is: ' + rulefolder_path)

    # TODO: remove snort3-deleted.rules (deleted.rules,experimental.rules,local.rules)

    # check for folder in folder (extraction is weird sometimes)
    try:
        f = listdir(rulefolder_path)
    except Exception:
        log.info('Directory does not exist, returning nothing: ' + rulefolder_path)
        return []
    if len(f) == 1:
        log.debug('rulefolder_path contains only one object: ' + str(f))
        if isdir(rulefolder_path + sep + f[0]):
            rulefolder_path += f[0] + sep
            log.debug('Updated rulefolder_path is: ' + rulefolder_path)

    all_rules = []

    rules_files = [f for f in scandir(rulefolder_path) if f.is_file() and
        f.name.endswith('.rules') and
        f.name != 'includes.rules' and
        f.name not in gc.ignore_rules_files]

    log.debug('Rules_files to process are: ')
    for r in rules_files:
        log.debug("\t" + r.path)

    for rule_file in rules_files:
        log.debug("Processing rules file: " + rule_file.name)
        # todo error handling on fopen
        with open(rule_file.path, 'r') as f:
            rules = f.readlines()
        log.debug("\t" + str(len(rules)) + " lines loaded.")

        for rule in rules:
            # remove all non-rule lines (leave commented out rules)
            if is_rule(rule) and not rule.startswith('###### PULLED BY MICROSOFT'):
                # build our 'rule' object
                all_rules.append({
                    'uid':          uid,  # noqa
                    'ruleset_type': ruleset_type,
                    'rule':         rule.strip(),  # noqa
                    'filename':     rule_file.name,  # noqa
                    'source_type':  source_type,  # noqa
                    'fingerprint':  fingerprint_rule(rule.strip())  # noqa
                })

    log.debug('Exiting function get_text_rules_from_folder. Returning ' + str(len(all_rules)) + ' actual rules (no comments).')

    return all_rules


def get_policy_from_file(path):
    '''
    Get the contents of a ips_policy file
    '''

    log.debug('Entering function get_policy_from_file. Path is: ' + path)

    enabled_rules = []

    try:
        with open(path, 'r') as f:
            enabled_rules = f.readlines()
    except Exception:
        log.warning("Error getting policy information from " + path)

    # make sure each element ends in a newline (for output reasons)
    for i, r in enumerate(enabled_rules):
        if not enabled_rules[i].endswith("\n"):
            enabled_rules[i] = r + "\n"

    # TODO: remove any entries that aren't actual policy entries (comments and whitespace)
    log.debug('Exiting function get_policy_from_file. Returning ' + str(len(enabled_rules)) + ' entries.')

    return enabled_rules


def fingerprint_rule(rule):
    '''
    Get a fingerprint (GID:SID:REV) from a rule
    '''

    gid = search(r'gid:(\d+);', rule)
    if not gid:
        gid = '1'  # (not all rules have this set even though they're supposed to)
    else:
        gid = gid.group(1)

    sid = search(r'sid:(\d+);', rule)
    if not sid:
        return None

    # rev sometimes has whitepsace
    rev = search(r'rev:\s*(\d+);', rule)
    if not rev:
        return None

    # fingerprint = gid.group(1) + ':' + sid.group(1) + ':' + rev.group(1)
    fingerprint = gid + ':' + sid.group(1) + ':' + rev.group(1)
    # print ("\t - Fingerprint is: " + fingerprint)

    return fingerprint


def load_local_rules():
    '''
    Process local rules files
    '''

    log.verbose("Loading local rules files.")

    # we can have many local rules files, in the 'config' section named local_rules*
    opts = gc.config.options('configuration')

    rules_to_return = []

    for opt in opts:
        if opt.startswith('local_rules'):
            path = gc.config['configuration'][opt]
            log.verbose('Processing local rules file: ' + path)

            if isfile(path):
                # todo error handling on fopen
                with open(path, 'r') as f:
                    rules = f.readlines()
            else:
                log.warning('Error, could not find local rulefile located at: ' + path)

            for rule in rules:
                s = is_rule(rule)
                if s:
                    rules_to_return.append({
                        'uid':          opt,  # noqa
                        'ruleset_type': None,
                        'rule':         s['rule'],  # noqa
                        'filename':     basename(path),  # noqa
                        'source_type':  'local',  # noqa
                        'fingerprint':  fingerprint_rule(rule.strip()),  # noqa
                        'enabled':      s['enabled']  # noqa
                    })

    log.verbose('Returning ' + str(len(rules_to_return)) + ' rules from all local rules files.')

    return rules_to_return


def get_blocklist_urls():
    '''
    Identify all blocklist URLs to download
    '''

    log.verbose("Identifying all blocklist URLs to download from.")
    urls = []   # array of strings

    if gc.config['blocklist'].getboolean('snort_blocklist'):
        log.verbose("- Will download Snort blocklist")
        urls.append(SNORT_BLOCKLIST_URL)
    if gc.config['blocklist'].getboolean('et_blocklist'):
        urls.append(ET_BLOCKLIST_URL)
        log.verbose("- Will download ET blocklist")

    for bl in gc.config.options('blocklist'):
        if bl.startswith('blocklist_'):
            log.verbose("- Will download Other blocklist: " + bl + ": " + str(gc.config['blocklist'][bl]))
            urls.append(gc.config['blocklist'][bl])

    log.verbose("Identified " + str(len(urls)) + " blocklist URLs to download.")
    return urls


def get_blocklists(start_time, urls):
    '''
    Get blocklist entries from URLs
    '''

    log.verbose("Downloading " + str(len(urls)) + " blocklists.")
    if not urls:
        return ''

    blocklist = "# BLOCKLIST CREATED BY " + SCRIPT_NAME.upper() + " ON " + start_time + "\n\n"  # array of strings, content of blocklists

    for url in urls:
        log.verbose("- Downloading " + url)
        # todo: error check
        try:
            r = requests.get(url)
        except Exception as e:
            log.warning('* Error downloading URL: ' + str(e))

        blocklist += "# " + SCRIPT_NAME + " - The follwing entries downloaded from: " + url + "\n\n" + r.text + "\n\n\n"

    return blocklist


def write_blocklists_to_file(bl):
    '''
    Write blocklist URLs to disk
    '''

    if not bl:
        log.verbose("No Blocklist entries to write to disk.")
        return

    # todo: try/catch error
    with open(gc.bocklist_outfile, 'w') as f:
        f.write(str(bl))


def write_rulesets_to_disk(rules, path):
    '''
    write the rulesets to a file (array of strings)
    '''

    log.debug('Entering Function write_rulesets_to_disk.')
    log.verbose('Preparing to write ' + str(len(rules)) + ' rules to ' + path)

    # if mode == simple, modify rule to comment-out disabled rules
    if gc.rule_mode == 'simple':
        for r in rules:
            if not r['enabled']:
                r['rule'] = '# ' + r['rule']

    # write all rules to disk. Sort the list first by UID, source_type, filename
    sorted_rules = sorted(rules, key=lambda k: (k['uid'], k['source_type'], k['filename']))

    header = ''

    # todo: try/catch error
    with open(path, 'w') as f:
        f.write("#-------------------------------------------------------------------\n")
        f.write("#  Rules file created by " + SCRIPT_NAME + " at " + gc.start_time + "\n")
        f.write("#  " + "\n")
        f.write("#  To Use this file: " + "\n")
        f.write("#  in your snort.lua, you need the following settings:" + "\n")
        f.write("#  set ips.include = '" + gc.rules_outfile + "',\n")
        if gc.rule_mode == 'policy':
            f.write("#  set detection.global_default_rule_state = false (this disables all rules by default)" + "\n")
            f.write("#  set ips.states = '" + gc.policy_path + "',\n")
        f.write("#  " + "\n")
        f.write("#-------------------------------------------------------------------\n\n")
        f.write("\n")
        for r in sorted_rules:
            if header != (r['uid'], r['source_type'], r['filename']):
                header = (r['uid'], r['source_type'], r['filename'])
                f.write("\n##### The following rules come from: " + r['uid'] + ' with sourcetype "' + r['source_type'] + '" from ' + r['filename'] + " #####\n\n")
            f.write(r['rule'] + "\n")
    log.debug('Exiting Function write_rulesets_to_disk.')


def write_state_to_disk(state, path):
    '''
    write the rulesets to a file (array of strings)
    '''

    log.debug('Entering Function write_policy_to_disk. ' + str(len(state)) + ' lines to write to: ' + path)

    # todo: try/catch error
    with open(path, 'w') as f:
        f.write("#-------------------------------------------------------------------\n")
        f.write("#  Policy file created by " + SCRIPT_NAME + " at " + gc.start_time + "\n")
        f.write("#  " + "\n")
        f.write("#  To Use this file with your rules file:" + "\n")
        f.write("#  in your snort.lua, you need the following settings:" + "\n")
        f.write("#  set detection.global_default_rule_state = false (this disables all rules by default)" + "\n")
        f.write("#  set ips.include = '" + gc.rules_outfile + "',\n")
        f.write("#  set ips.states = '" + gc.policy_path + "',\n")
        f.write("#  " + "\n")
        f.write("#-------------------------------------------------------------------\n\n")
        f.writelines(state)
        f.write("\n")

    log.debug('Exiting Function write_policy_to_disk.')


def is_rule(rule):
    '''
    Determine if a string is a valid rule (rule can be commented out
        and still be true)
    input: string.
    output: False if NOT a rule (comment or blank line)
            {enabled=bool, rule=...}
    '''

    rule = rule.strip()
    m = match(r'^[\s#]*.*\(.*sid:.*\)\s*$', rule)

    # edge case
    if rule.startswith('###### PULLED BY MICROSOFT'):
        return False

    if not m:
        return False
    else:
        # is a rule, determine if is enabled
        enabled = not rule.startswith('#')

        # strip all leading hash / whitespace from rule
        rule = rule.strip("#\n\t ")

        return {'enabled': enabled, 'rule': rule}


def print_environment(gc):
    '''
    Print environment Information
    '''

    # todo: get distro
    # todo: convert print to 'log'
    log.verbose(f'Running {VERSION_STR}')
    log.verbose("Verbosity (-v or -vv) flag enabled. Verbosity level is: " + log.level.name)
    log.debug('Start time is: ' + gc.start_time)
    log.debug('Command-line arguments (argv) are:' + str(argv))
    log.debug("Parsed command-line arguments are (including defaults):")
    for k, v in sorted(vars(gc.args).items()):
        log.debug("\t" + str(k) + ' = ' + str(v))
    log.debug('Platform is:' + platform() + '; ' + version())
    log.debug('uname is: ' + str(uname()))
    log.debug('System is: ' + str(system()))
    log.debug('Python: ' + str(python_version()))
    log.debug("architecture is: " + str(architecture()[0]))
    log.debug("PWD is: " + str(environ.get('PWD')))
    log.debug("SHELL is: " + str(environ.get('SHELL')))
    log.debug('OS Path Separator is: ' + sep)


def get_temp_directory(start_time):
    '''
    Create a temp directory
    '''

    #   First check if temp dir is specified in configuration, otherwise
    #   use system temp dir
    log.debug('Determining what temporary directory path to use.')

    log.debug("\tChecking if temp_path is specified in config file.")

    if gc.config.has_option('configuration', 'temp_path'):
        tmp = gc.config['configuration']['temp_path'] + sep + SCRIPT_NAME + '-' + start_time
        log.debug("\ttemp_path is specified in config file. Will try using: " + tmp)
    else:
        tmp = gettempdir() + sep + SCRIPT_NAME + '-' + start_time
        log.debug("\ttemp_path is not specified in config file. Will try using: " + tmp)

    log.debug("\tTrying to create new Temp working file: " + tmp)
    try:
        mkdir(tmp)
        mkdir(tmp + sep + 'downloaded_rulesets')
        mkdir(tmp + sep + 'extracted_rulesets')
        if(gc.process_so_rules):
            mkdir(tmp + sep + 'so_rules')
    except OSError:
        log.error("Fatal Error: Creation of the temporary working directory %s failed" % tmp)
    else:
        log.debug("\tSuccessfully created the temp directory %s " % tmp)

    return tmp


def get_snort_version():
    '''
    Determine the Version of Snort
    '''

    log.debug("Determining Snort version from config file or from Snort binary.")
    # first check the config file
    if gc.config.has_option('snort', 'snort_version'):
        log.debug("\tDetermining snort version from config file.")
        v = gc.config['snort']['snort_version']
        log.debug("\tsnort version number from config file is: " + v)
        return v

    # otherwise check the binary. First determine where the binary resides
    if gc.config.has_option('snort', 'snort_path'):
        command = gc.config['snort']['snort_path'] + ' -V'
        log.debug("\tTrying to determine snort version from binary specified in configuration at snort_path: " + command)
    else:
        command = "snort -V"  # the shell command
        log.debug("\tTrying to determine snort version from binary on system path: " + command)

    # call the snort binary with -V flag
    try:
        process = Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
        output, error = process.communicate()
    except Exception as e:
        log.error('Fatal error determining snort version from binary:' + str(e))

    # check return call for error
    if error:
        log.error('Fatal error determining snort version from binary:' + process.returncode + ' ' + error.strip())

    # parse stdout from snort binary to determine version number
    log.debug("\tOutput from Snort binary with -V flag is: \n" + str(output) + "\n")
    x = search(r"Version [-\.\d\w]*", str(output))
    log.verbose("\tsnort version number from executable is: " + x.group()[8:])
    return x.group()[8:]


def get_distro():
    '''
    Determine the current distro
    '''

    log.debug("Determining distro from config file or from OS.")

    # first check the config file
    if gc.config.has_option('configuration', 'distro'):
        log.debug("\tDetermining distro from config file.")
        v = gc.config['configuration']['distro']
        log.debug("\tdistro from config is " + v)
        return v
    # if not config file, try to determine from OS
    # todo:
    return None


def get_policy():
    '''
    Determine the current ips policy
    See: https://www.snort.org/faq/why-are-rules-commented-out-by-default
    '''

    log.debug("Determining policy from config file.")

    valid_policies = ['none', 'connectivity', 'balanced', 'security', 'max-detect']

    # check the config file
    if gc.config.has_option('configuration', 'ips_policy'):
        log.debug("\tDetermining policy from config file.")
        policy = gc.config['configuration']['ips_policy'].lower()
    else:
        log.debug('No ips_policy found, defaulting to "connectivity"')
        policy = 'connectivity'

    if policy not in valid_policies:
        log.error('Invalid ips_policy found: ' + policy)

    log.debug('ips_policy is: ' + policy)

    # convert policy to actual filename
    if policy == 'connectivity':
        return 'rulestates-connectivity-ips.states'
    elif policy == 'balanced':
        return 'rulestates-balanced-ips.states'
    elif policy == 'security':
        return 'rulestates-security-ips.states'
    elif policy == 'max-detect':
        return 'rulestates-max-detect-ips.states'
    else:
        return 'none'


# *****************************************************************************
# *****************************************************************************
#
#                       Grammar / parsing functions
#
# *****************************************************************************
# *****************************************************************************

def stringify_rules(rules):
    '''
    Convert a rule dict object to a string
    '''

    # input can be a list or single rule object (dict). we need a list regardless
    if isinstance(rules, dict):
        rules = [rules]

    log.debug("We have received " + str(len(rules)) + ' rule objects in stringify_rules.')

    all_rules = []
    c = 0
    for rule in rules:
        c += 1
        rule_str = ''

        # is rule enabled
        if not rule['enabled']:
            rule_str = '# '

        rule_str += rule['action'] + ' '

        # Process optional Header items in order
        if 'protocol' in rule:
            rule_str += rule['protocol'] + ' '
        if 'src_network' in rule:
            rule_str += rule['src_network'] + ' '
        if 'src_ports' in rule:
            rule_str += rule['src_ports'] + ' '
        if 'direction' in rule:
            rule_str += rule['direction'] + ' '
        if 'dst_network' in rule:
            rule_str += rule['dst_network'] + ' '
        if 'dst_ports' in rule:
            rule_str += rule['dst_ports'] + ' '

        rule_str += '( '

        # options are a dict held in the 'options' key
        # the value might be a list if there were multiple options with
        # the same name

        for k, v in rule['options'].items():
            # first check if there's a value for this key
            if v:
                # we have both key and value. but value may be a list
                if isinstance(v, list):
                    for i in v:
                        # append each value in list with same key
                        rule_str += k + ':' + i + '; '
                else:
                    rule_str += k + ':' + v + '; '
            else:
                # just write the key w/o value
                rule_str += k + '; '
        rule_str += ')'

        all_rules.append(rule_str)
        # print(str(c) + "\t" + str(len(all_rules)))

    log.debug("We are returning " + str(len(all_rules)) + ' rule objects from stringify_rules.')
    return all_rules


if __name__ == "__main__":
    main()
