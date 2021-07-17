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
from json import load                       # to load json manifest file in lightSPD
from os import environ, listdir, scandir, mkdir, kill
from os.path import isfile, join, sep, abspath, basename, isdir
from platform import platform, version, uname, system, python_version, architecture
from re import search, sub, match
from shutil import rmtree, copy             # remove directory tree, python 3.4+
try:
    from signal import SIGHUP               # linux/bsd, not windows
except ImportError:
    #from ctypes import CDLL, c_raise,      # Windows reload process (not yet implemented)
    pass
from subprocess import Popen, PIPE          # to get Snort version from binary
from sys import exit, argv                  # print argv and  sys.exit
from tarfile import open as open_tar        # to extract tgz ruleset file
from urllib.parse import urlsplit           # get filename from url

# Third-party libraries
import requests

# Our PulledPork3 internal libraries
from lib import config, logger
from lib.snort import Blocklist, Rules, Policies


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

    # Print the env
    print_environment(gc)

    # Also setup halt on warn as requested
    log.halt_on_warn = not gc.args.ignore_warn

    # Save from args
    gc.delete_temp_path = not gc.args.keep_temp_dir

    # Load the configuration File from command line (-c FILENAME). Verify exists, and only 1 entry.
    if not gc.args.configuration:
        log.error("The following arguments are required: -c/--configuration <file>")
    if len(gc.args.configuration) > 1:
        log.warning('Multiple entries passed as -c/--configuration.  Only a single entry permitted.')

    config_file = gc.args.configuration[0]  # this is a list of one element

    # load configuration file
    log.info(f'Loading configuration file: {config_file}')
    try:
        gc.load(config_file)
    except Exception as e:
        log.error(f'Unable to load configuration file: {e}')

    # Attempt to validate the config
    gc.validate()

    # Update logging if we're not printing the oinkcode
    if gc.oinkcode and not gc.args.print_oinkcode:
        log.add_hidden_string(gc.oinkcode)

    # Create a temp working directory (path stored as a string)
    gc.tempdir = get_temp_directory(gc.temp_path, gc.start_time)
    log.verbose("Temporary working directory is: " + gc.tempdir)

    # Are we missing the Snort version in config?
    if not gc.defined('snort_version'):
        gc.snort_version = get_snort_version(gc.get('snort_path'))

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

    all_new_rules = Rules()
    all_new_policies = Policies() 

    for rule_set in extracted_rulesets:
        log.debug('---------------------------------')
        log.debug("Working on Ruleset: " + rule_set[0] + ' - ' + rule_set[1])

        # determine ruleset type:
        if rule_set[0] == 'SNORT_COMMUNITY':
            # only simple rules to worry about
            # community rules have an extra folder to delve into
            rule_path = rule_set[1] + sep + 'snort3-community-rules'

            # todo: wrap next line in try/catch
            community_rules = Rules(rule_path, gc.ignore)
            log.verbose(f'\tLoaded community rules: {str(community_rules)}')
            all_new_rules.extend(community_rules)

            # ? how to create a policy file from these rules?
            # all_new_policies.extend(???)

        elif rule_set[0] == 'SNORT_REGISTERED':

            # process text rules
            text_rules_path = str(rule_set[1] + sep + 'rules')
            registered_rules = Rules(text_rules_path, gc.ignore)
            registered_policies = Policies(text_rules_path)

            log.verbose(f'* Text Rules processed from Registered ruleset: {str(registered_rules)}')
            log.verbose(f'* Text Policies processed from Registered ruleset: {str(registered_policies)}')

            # process builtin rules
            builtin_rules_path = str(rule_set[1] + sep + 'builtins')

            builtin_rules = Rules(builtin_rules_path)
            builtin_policies = Policies(builtin_rules_path)

            log.verbose(f'* Builtin Rules processed from Registered ruleset: {str(builtin_rules)}')
            log.verbose(f'* Builtin Policies processed from Registered ruleset: {str(builtin_policies)}')

            registered_rules.extend(builtin_rules)
            registered_policies.extend(builtin_policies)

            # process so rules
            if gc.get('sorule_path'):
                # copy files first to temp\so_rules folder (we'll copy them all at the end, this checks for dupes)
                # todo: error handling
                so_src_folder = join(rule_set[1], 'so_rules', 'precompiled', gc.distro)
                src_files = listdir(so_src_folder)
                for file_name in src_files:
                    full_file_name = join(so_src_folder, file_name)
                    if isfile(full_file_name):
                        copy(full_file_name, join(gc.tempdir, 'so_rules'))

                # get SO rule stubs
                # todo: generate stubs if distro folder doesn't exist
                so_rules_path = str(rule_set[1] + sep + 'so_rules')

                so_rules = Rules(so_rules_path)
                so_policies = Policies(so_rules_path)

                log.verbose(f'* SO Rules processed from Registered ruleset: {str(so_rules)}')
                log.verbose(f'* SO Policies processed from Registered ruleset: {str(so_policies)}')

                registered_rules.extend(so_rules)
                registered_policies.extend(so_policies)

            log.verbose(f'* Rules processed from Registered ruleset: {str(registered_rules)}')
            log.verbose(f'* Policies processed from Registered ruleset: {str(registered_policies)}')

            log.verbose(f'Preparing to apply policy {gc.ips_policy} to Registered rules')
            log.verbose (f' - Registered rules before policy application:  {str(registered_rules)}')

            # apply the policy to these rules
            registered_rules.apply_policy(registered_policies[gc.ips_policy])  
            log.verbose (f' - Registered rules after policy application:  {str(registered_rules)}')

            all_new_rules.extend(registered_rules)
            all_new_policies.extend(registered_policies)

        elif rule_set[0] == 'SNORT_LIGHTSPD':

            lightspd_rules = Rules()
            lightspd_policies = Policies()

            # the manifest.json file is only used (at this time) for processing .so rules
            if gc.get('sorule_path'):

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
                    #r = get_text_rules_from_folder(so_rules_path, 'SNORT_LIGHTSPD', 'snort_ruleset', 'so')
                    #rules.extend(r)
                    lightspd_rules = Rules(so_rules_path)
                    lightspd_policies = Policies(so_rules_path)

                log.verbose(f'* SO Rules processed from LightSPD ruleset: {str(lightspd_rules)}')
                log.verbose(f'* SO Policies processed from LightSPD ruleset: {str(lightspd_policies)}')
    
            # LOAD TEXT RULES FROM LightSPD archive
            # right now, the LightSPD archive only has a 3.0.0.0 folder in it, so let's use that explicitly.
            # this should hopefully be changed to an explicit entry in the manifest.json file
            text_rules_path = rule_set[1] + sep + 'lightspd' + sep + 'rules' + sep + '3.0.0.0' + sep

            lightspd_text_rules = Rules(text_rules_path,gc.ignore)
            lightspd_text_policies = Policies(text_rules_path)

            log.verbose(f'* text Rules processed from LightSPD ruleset: {str(lightspd_text_rules)}')
            log.verbose(f'* text Policies processed from LightSPD ruleset: {str(lightspd_text_policies)}')

            lightspd_rules.extend(lightspd_text_rules)
            lightspd_policies.extend(lightspd_text_policies)

            # LOAD BULTIN RULES FROM LightSPD archive
            # right now, the LightSPD folder has a single 3.0.1-3 folder in it, so let's use that explictly
            # hopefully this will be changed to an explicit entry in the manifest.json file
            builtin_rules_path = str(rule_set[1] + sep + 'lightspd' + sep + 'builtins' + sep + '3.0.0-264')
            lightspd_builtin_rules = Rules(builtin_rules_path, gc.ignore)
            lightspd_builtin_policies = Policies(builtin_rules_path)

            log.verbose(f'* builtin Rules processed from LightSPD ruleset: {str(lightspd_builtin_rules)}')
            log.verbose(f'* builtin Policies processed from LightSPD ruleset: {str(lightspd_builtin_policies)}')

            lightspd_rules.extend(lightspd_builtin_rules)
            lightspd_policies.extend(lightspd_builtin_policies)

            log.verbose(f'Preparing to apply policy {gc.ips_policy} to LightSPD rules')
            log.verbose (f' - LightSPD rules before policy application:  {str(lightspd_rules)}')

            # apply the policy to these rules
            lightspd_rules.apply_policy(lightspd_policies[gc.ips_policy])  
            log.verbose (f' - LightSPD rules after policy application:  {str(lightspd_rules)}')

            all_new_rules.extend(lightspd_rules)
            all_new_policies.extend(lightspd_policies)  

        else:
            log.warning("Unknown ruleset archive folder recieved.")
            # TODO: non-standard ruleset, we need to figure it out

    log.info(f'Competed processing all rulesets')
    log.info(f'* Total Rules: {str(all_new_rules)}')

    for path in gc.local_rules:
        local_rules = Rules(path)
        log.info(f'loaded local rules file: {str(local_rules)} from {path}')
        all_new_rules.extend(local_rules)

    log.info(f'Competed processing all rulesets and local rules')
    log.info(f'* Total Rules: {str(all_new_rules)}')

    # Prepare rules for output
    log.info(f'writing rules to {gc.rule_path}')
    header = ("#-------------------------------------------------------------------\n"
            "#  Rules file created by " + SCRIPT_NAME + " at " + gc.start_time + "\n"
            "#  " + "\n"
            "#  To Use this file: " + "\n"
            "#  in your snort.lua, you need the following settings:" + "\n"
            "#  set ips.include = '" + gc.rule_path + "',\n")
    if gc.rule_mode == 'policy':
        header = header + ("#  set detection.global_default_rule_state = false (this disables all rules by default)" + "\n"
                "#  set ips.states = '" + gc.policy_path + "',\n"
                "#  " + "\n")
    header = header + "#-------------------------------------------------------------------\n\n"

    all_new_rules.write_file(gc.rule_path, gc.include_disabled_rules, header)

    # write the policy to disk
    if gc.policies_path:
        log.info(f'writing policy file to {gc.policies_path}')
        (all_new_policies[gc.ips_policy]).write_file(gc.policies_path)
            
    # copy .so rules from tempdir
    # todo: delete old rules
    if gc.get('sorule_path'):
        so_src_folder = join(gc.tempdir, 'so_rules')
        src_files = listdir(so_src_folder)
        for file_name in src_files:
            full_file_name = join(so_src_folder, file_name)
            if isfile(full_file_name):
                copy(full_file_name, gc.sorule_path)

    # -----------------------------------------------------------------------------
    # Download Blocklists

    # Have a blocklist out file defined?
    if gc.defined('blocklist_path'):

        # Prepare an empty blocklist
        log.info("Preparing to process blocklists.")
        new_blocklist = Blocklist()

        # Downloading the Snort blocklist?
        if gc.snort_blocklist:
            log.verbose('Downloading the Snort blocklist')
            try:
                new_blocklist.download_url(SNORT_BLOCKLIST_URL)
            except Exception as e:
                log.warning(f'Unable to download the Snort blocklist: {e}')

        # ET blocklist?
        if gc.et_blocklist:
            log.verbose('Downloading the ET blocklist')
            try:
                new_blocklist.download_url(ET_BLOCKLIST_URL)
            except Exception as e:
                log.warning(f'Unable to download the ET blocklist: {e}')

        # Any other blocklists
        for bl_url in gc.blocklist_urls:
            log.verbose(f'Downloading the blocklist: {bl_url}')
            try:
                new_blocklist.download_url(bl_url)
            except Exception as e:
                log.warning(f'Unable to download blocklist: {e}')

        # Compose the blocklist header and write the blocklist file
        blocklist_header = f'# BLOCKLIST CREATED BY {SCRIPT_NAME.upper()} ON {gc.start_time}'
        try:
            new_blocklist.write_file(gc.blocklist_path, blocklist_header)
        except Exception as e:
            log.warning(f'Unable to write blocklist: {e}')

    # -----------------------------------------------------------------------------
    # Relad Snort

    # Have a PID file defined?
    if gc.defined('pid_path'):

        with open(gc.pid_path, 'r') as f:
            pid = f.readline().strip()
            pid = int(pid)

        kill(pid, SIGHUP)   # does not work on windows, see below

        # windows SIGHUP
        # import ctypes
        # ucrtbase = ctypes.CDLL('ucrtbase')
        # c_raise = ucrtbase['raise']
        # c_raise(some_signal)

    # -----------------------------------------------------------------------------
    # Delete temp dir
    if not gc.delete_temp_path:
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


def print_operational_settings():
    '''
    Print all the operational settings after parsing (what we will do)
    '''

    log.verbose('------------------------------------------------------------')
    log.verbose("After parsing the command line and configuration file, this is what I know:")

    # halt-on-error
    if gc.args.ignore_warn:
        log.verbose('Warnings will not cause this program to terminate (damn the torpedos, full speed ahead!).')
    else:
        log.verbose('Program will terminate when encountering an error or warning.')

    # are we printing oinkcode?
    if gc.args.print_oinkcode:
        log.verbose('Oinkcode will NOT be obfuscated in the output (do not share your oinkcode).')
    else:
        log.verbose('Oinkcode will be obfuscated in the output (this is a good thing).')

    # Temp dir management
    log.verbose('Temporary working directory is: ' + gc.tempdir)

    if gc.delete_temp_path:
        log.verbose('Temporary working directory will be deleted at the end.')
    else:
        log.verbose('Temporary working directory will not be deleted at the end.')

    # env. variables
    log.verbose('The Snort version number used for processing is: ' + gc.snort_version)
    if gc.distro:
        log.verbose('The distro used for processing is: ' + gc.distro)
    log.verbose('The ips policy used for processing is: ' + gc.ips_policy)

    if gc.get('sorule_path'):
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
        if gc.registered_ruleset:
            log.verbose("\tSnort Registered Ruleset")
        if gc.community_ruleset:
            log.verbose("\tSnort Community Ruleset")
        if gc.lightspd_ruleset:
            log.verbose("\tSnort LightSPD Ruleset")

    #   Rules
    if gc.ignore:
        log.verbose('The following rules files will not be included in rulesets: ' + str(gc.ignore))

    log.verbose("Rule Output mode is: " + gc.rule_mode)
    if gc.rule_mode == 'policy':
        log.verbose('Policy file to write is: ' + gc.policy_path)

    # local rules files
    for opt in gc.local_rules:
        log.verbose('Rules from Local rules file will be included: ' + opt)

    log.verbose("All Rules will be written to a single file: " + gc.rule_path)
    if gc.include_disabled_rules:
        log.verbose("Disabled rules will be written to the rules file")
    else:
        log.verbose("Disabled rules will not be written to the rules file")

    # policys
    log.verbose('The rule_mode is: ' + gc.rule_mode)
    if gc.rule_mode == 'policy':
        log.verbose('the policy file written (to specify enabled rules) is: ' + gc.policy_path)

    # blocklists
    if gc.snort_blocklist:
        log.verbose("Snort blocklist will be downloaded")
    if gc.et_blocklist:
        log.verbose("ET blocklist will be downloaded")

    for bl in gc.blocklist_urls:
        log.verbose("Other blocklist will be downloaded: " + bl)

    if not any([gc.snort_blocklist, gc.et_blocklist, len(gc.blocklist_urls)]):
        log.verbose("No Blocklists will be downloaded.")
    else:
        log.verbose('Blocklist entries will be written to: ' + gc.blocklist_path)

    # reload snort
    if gc.defined('pid_path'):
        log.verbose('Snort will be reloaded with new configuration, Pid loaded from: ' + gc.pid_path)
    else:
        log.verbose('Snort will NOT be reloaded with new configuration.')

    log.verbose('------------------------------------------------------------')


def determine_ruleset_urls():
    '''
    return a list of full URLs to download rulesets (TGZ) from
    in: nothing (pulls info from global config )
    out: list of entries, each entry is a tuple (source_ID, url)
         source_ID is to tell us where we got the entry
    '''

    urls = []

    if gc.community_ruleset:
        u = ('SNORT_COMMUNITY', RULESET_URL_SNORT_COMMUNITY)
        urls.append(u)

    if gc.registered_ruleset:
        r = RULESET_URL_SNORT_REGISTERED.replace('<OINKCODE>', gc.oinkcode)
        version = sub(r'[^a-zA-Z0-9]', '', gc.snort_version)  # version in URL is alphanumeric only
        r = r.replace('<VERSION>', version)
        u = ('SNORT_REGISTERED', r)
        urls.append(u)

    if gc.lightspd_ruleset:
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


def get_temp_directory(temp_path, start_time):
    '''
    Create a temp directory
    '''

    #   First check if temp dir is specified in configuration, otherwise
    #   use system temp dir
    log.debug('Determining what temporary directory path to use.')

    tmp = join(temp_path, SCRIPT_NAME + '-' + start_time)
    log.debug("\tWill try using: " + tmp)

    log.debug("\tTrying to create new Temp working file: " + tmp)
    try:
        mkdir(tmp)
        mkdir(join(tmp, 'downloaded_rulesets'))
        mkdir(join(tmp, 'extracted_rulesets'))
        if(gc.get('sorule_path')):
            mkdir(join(tmp, 'so_rules'))
    except OSError:
        log.error("Fatal Error: Creation of the temporary working directory %s failed" % tmp)
    else:
        log.debug("\tSuccessfully created the temp directory %s " % tmp)

    return tmp


def get_snort_version(snort_path=None):
    '''
    Determine the Version of Snort
    '''

    log.debug("Determining Snort version from Snort binary.")

    # Default to just "snort" if no path provided
    snort_path = snort_path or 'snort'

    # Run snort to attempt to find the version
    command = f'{snort_path} -V'

    log.debug(f'\tTrying to determine snort version using: {command}')

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
    x = search(r"Version ([-\.\d\w]+)", str(output))
    if not x:
        log.error('Unable to grok version number from Snort output')
    log.verbose("\tsnort version number from executable is: " + x[1])
    return x[1]


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
