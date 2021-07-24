import io
import os
import re
import hashlib
import tarfile
from enum import Enum

import requests

from . import logger


################################################################################
# Logging
################################################################################

log = logger.Logger()


################################################################################
# Constants
################################################################################

# Rule regex patterns
RULE_REGEX = re.compile(r'^(#\s*)?(\w+)\s(.*\(.+sid:(\d+);.+\))\s*$')
RULE_GID_REGEX = re.compile(r'gid:(\d+);')
RULE_REV_REGEX = re.compile(r'rev:(\d+);')
POLICY_RULE_REGEX = re.compile(r'^(\w+) \(gid:(\d+?); sid:(\d+?); (\w+);\)$')

# Ruleset file lists to check for RulesArchive ruleset guessing
RULESET_COMMUNITY_FILE_CHECKS = [
    'snort3-community-rules/snort3-community.rules',
    'snort3-community-rules/sid-msg.map'
]
RULESET_REGISTERED_FILE_CHECKS = [
    'builtins/builtins.rules',
    'etc/snort_defaults.lua',
    'rules/rulestates-balanced-ips.states',
    'so_rules/includes.rules',
    'so_rules/src'
]
RULESET_LIGHTSPD_FILE_CHECKS = [
    'lightspd/manifest.json',
    'lightspd/builtins/',
    'lightspd/rules/',
    'lightspd/modules/src/Makefile',
    'lightspd/policies/common/'
]


################################################################################
# Enums
################################################################################

# Rulesets enum
class RulesetTypes(Enum):
    COMMUNITY = 'Community Ruleset'
    REGISTERED = 'Registered Ruleset'
    LIGHTSPD = 'LightSPD Ruleset'
    UNKNOWN = 'Unknown Ruleset'


################################################################################
# Blocklist - Helps with the management of blocklists
################################################################################

class Blocklist(object):

    def __init__(self, filename=None, url=None):
        '''
        Setup the new blocklist

        Example:
        >>> bl = Blocklist()
        >>> bl
        Blocklist(lines:0)
        >>>
        >>> bl = Blocklist(filename='../blocklists/snort.txt')
        >>> bl
        Blocklist(lines:1495)
        >>>
        >>> bl = Blocklist(url='https://snort.org/downloads/ip-block-list')
        >>> bl
        Blocklist(lines:1495)
        '''

        # Where we'll keep the blocklist lines
        self._lines = []

        # Are we loading a blocklist file?
        if filename:
            self.load_file(filename)

        # Are we loading from a URL?
        if url:
            self.load_url(url)

    def __repr__(self):
        return f'Blocklist(lines:{len(self)})'

    def __len__(self):
        '''
        Return the number of lines in the Blocklist

        Example:
        >>> bl = Blocklist('../blocklists/snort.txt')
        >>> bl
        Blocklist(lines:1495)
        >>>
        >>> len(bl)
        1495
        '''
        return len(self._lines)

    def __contains__(self, block):
        '''
        Return whether a block entry is in the Blocklist object
        This will also match comments

        Example:
        >>> bl = Blocklist('../blocklists/snort.txt')
        >>> bl
        Blocklist(lines:1495)
        >>>
        >>> '178.175.23.87' in bl
        True
        >>> 'smurf' in bl
        False
        '''
        return block in self._lines

    def __iter__(self):
        '''
        Start the enumeration
        '''
        self._iter = self._lines.__iter__()
        return self

    def __next__(self):
        '''
        Get the next block in the enumeration

        Example:
        >>> bl = Blocklist('../blocklists/snort.txt')
        >>> bl
        Blocklist(lines:1495)
        >>>
        >>> for block in bl:
        ...     block
        ...     break
        ...
        '178.175.23.87'
        '''
        block = self._iter.__next__()
        return block

    def __getitem__(self, line):
        '''
        Allows for getting blocks using: bl[0]

        Example:
        >>> bl = Blocklist('../blocklists/snort.txt')
        >>> bl
        Blocklist(lines:1495)
        >>>
        >>> bl[0]
        '178.175.23.87'
        '''
        block = self._lines[line]
        return block

    def extend(self, blocklist, source=None):
        '''
        Extend this blocklist from another

        Example:
        >>> bl = Blocklist()
        >>> bl
        Blocklist(lines:0)
        >>> bl2 = Blocklist('../blocklists/snort.txt')
        >>> bl2
        Blocklist(lines:1495)
        >>>
        >>>
        >>> bl.extend(bl2)
        >>> bl
        Blocklist(lines:1495)
        '''

        # Get a list of blocklist lines to process
        if isinstance(blocklist, str):
            blocklist = blocklist.splitlines()
        elif isinstance(blocklist, Blocklist):
            if source is None:
                source = 'Blocklist Object'
            blocklist = blocklist._lines.copy()
        elif not isinstance(blocklist, (list, tuple)):
            raise ValueError(f'Unexpected blocklist to apply:  {blocklist}')

        # Set source if not set
        if source is None:
            source = 'UNDEFINED'

        # Add a comment to indicate the source of following list entries
        if len(blocklist):
            self._lines.append(f'# Blocklist Source:  {source}')

        # Work through the lines of the blocklist
        for line in blocklist:

            # Strip the line
            line = line.strip()

            # Empty lines will be dropped
            if not line:
                continue

            # Apply all comments
            if line.startswith('#'):
                self._lines.append(line)

            # De-dupe the lines on ingest
            if line in self._lines:
                continue

            # Add the new line
            self._lines.append(line)

    def clear(self):
        '''
        Clear the blocklist
        '''
        self._lines.clear()

    def load_url(self, blocklist_url):
        '''
        Load a blocklist from a URL and add it to this blocklist

        Example:
        >>> bl = Blocklist()
        >>> bl
        Blocklist(lines:0)
        >>>
        >>> bl.load_url('https://snort.org/downloads/ip-block-list')
        >>> bl
        Blocklist(lines:1495)
        '''

        # Download the URL, and check response status
        resp = requests.get(blocklist_url)
        resp.raise_for_status()

        # Extend this blocklist with the downloaded content
        self.extend(resp.text, source=f'url - {blocklist_url}')

    def load_file(self, blocklist_file):
        '''
        Load a local file into this blocklist

        Example:
        >>> bl = Blocklist()
        >>> bl
        Blocklist(lines:0)
        >>>
        >>> bl.load_file('../blocklists/snort.txt')
        >>> bl
        Blocklist(lines:1495)
        '''

        # Open the blocklist file and read all the lines
        with open(blocklist_file, 'r') as fh:
            blocklist = fh.readlines()

            # Extend this blocklist with the loaded file
            self.extend(blocklist, source=f'file - {blocklist_file}')

    def write_file(self, blocklist_file, header=None):
        '''
        Write this blocklist to a file

        Example:
        >>> bl = Blocklist('../blocklists/snort.txt')
        >>> bl
        Blocklist(lines:1495)
        >>>
        >>> bl.write_file('pp-blocklist.txt')
        '''

        # Open the file for writing
        with open(blocklist_file, 'w') as fh:

            # Write a file header?
            if header is not None:
                fh.write(f'{header}\n')

            # Write all of theb locklist lines
            fh.write('\n'.join(self._lines))


################################################################################
# Rule - Represents an individual Snort rule, state, and metadata
################################################################################

class Rule(object):

    def __init__(self, rule, **metadata):
        '''
        Parse the provided rule string into a Rule object

        Example:
        >>> r = Rule('alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; content:"test"; sid:1000000001; rev:1;)')
        >>> r
        Rule(rule_id:1:1000000001, action:alert, state:ENABLED)
        >>>
        >>> r = Rule('# alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; content:"test"; sid:1000000001; rev:1;)')
        >>> r
        Rule(rule_id:1:1000000001, action:alert, state:DISABLED)
        '''

        # Use regex to parse the rule bits
        rule_parts = RULE_REGEX.match(rule)

        # If not a rule, move on
        if rule_parts is None:
            raise ValueError('Rule text was not able to be parsed')

        # Save the easy bits
        self._raw = rule_parts[3]
        self.sid = rule_parts[4]
        self.action = rule_parts[2]
        self.state = rule_parts[1] is None
        self.metadata = metadata.copy()

        # Parse harder rule bits
        gid = RULE_GID_REGEX.search(rule)
        self.gid = gid[1] if gid is not None else '1'
        rev = RULE_REV_REGEX.search(rule)
        self.rev = rev[1] if rev is not None else '0'

    def __repr__(self):
        return f'Rule(rule_id:{self.rule_id}, action:{self.action}, state:{"ENABLED" if self.state else "DISABLED"})'

    @property
    def rule_id(self):
        '''
        Return the rule ID: GID:SID
        Do we want the rev also represented here?

        Example:
        >>> r = Rule('alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; content:"test"; sid:1000000001; rev:1;)')
        >>> r
        Rule(rule_id:1:1000000001, action:alert, state:ENABLED)
        >>>
        >>> r.rule_id
        '1:1000000001'
        '''
        return f'{self.gid}:{self.sid}'

    @property
    def text(self):
        '''
        Return the rule text with the current action, ignoring state

        Example:
        >>> r = Rule('alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; content:"test"; sid:1000000001; rev:1;)')
        >>> r
        Rule(rule_id:1:1000000001, action:alert, state:ENABLED)
        >>>
        >>> r.text
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; flow:established,to_server; content:"test"; sid:1000000001; rev:1;)'
        >>> r.action = 'block'
        >>> r.text
        'block tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; flow:established,to_server; content:"test"; sid:1000000001; rev:1;)'
        '''
        return f'{self.action} {self._raw}'

    @property
    def stateful_text(self):
        '''
        Return the enabled or disabled (commented-out) rule text

        Example:
        >>> r = Rule('alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; content:"test"; sid:1000000001; rev:1;)')
        >>> r
        Rule(rule_id:1:1000000001, action:alert, state:ENABLED)
        >>>
        >>> r.stateful_text
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; flow:established,to_server; content:"test"; sid:1000000001; rev:1;)'
        >>> r.state = False
        >>> r.stateful_text
        '# alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; flow:established,to_server; content:"test"; sid:1000000001; rev:1;)'
        '''
        if self.state:
            return self.text
        return f'# {self.text}'

    def copy(self):
        '''
        Return a new copy of the rule

        Example:
        >>> r = Rule('alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; content:"test"; sid:1000000001; rev:1;)')
        >>> r
        Rule(rule_id:1:1000000001, action:alert, state:ENABLED)
        >>>
        >>> r2 = r.copy()
        >>> r2
        Rule(rule_id:1:1000000001, action:alert, state:ENABLED)
        '''

        # Create a new copy of the rule and return it
        new_rule = Rule(self.stateful_text, **self.metadata)
        return new_rule


################################################################################
# Rules - A collection of Rule objects
################################################################################

class Rules(object):

    def __init__(self, rules_path=None, ignored_files=[], **metadata):
        '''
        Load all the rule files from the given rules path, except those
        that will be ignored

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        '''

        # Setup the rules cache and save the metadata
        self._all_rules = {}
        self.metadata = metadata

        # No rules to process?
        if rules_path is None:
            return

        # Is source a directory?
        if os.path.isdir(rules_path):

            # Work through the files in the given path
            for rules_file in os.scandir(rules_path):

                # Check for rules files, and those we don't want
                if not rules_file.name.endswith('.rules'):
                    continue
                if rules_file.name in ignored_files:
                    continue

                # Attempt to load the file
                self.load_file(rules_file.path)

        # Is it a fiie?
        elif os.path.isfile(rules_path):

            # This disregards the ignored file lists

            # Attempt to load the file
            self.load_file(rules_path)

        # File or folder not present, raise an exception
        else:
            raise FileNotFoundError(rules_path)

    def __repr__(self):

        # Count the rules
        total = len(self._all_rules)
        enabled = 0
        for rule in self._all_rules.values():
            if rule.state:
                enabled += 1

        return f'Rules(loaded:{total}, enabled:{enabled}, disabled:{total - enabled})'

    def __len__(self):
        '''
        Return the number of loaded rules

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> len(txt)
        41987
        '''
        return len(self._all_rules)

    def __contains__(self, rule):
        '''
        Return whether a rule is in the Rules object

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> '1:10018' in txt
        True
        '''

        # If it's a string, easy
        if isinstance(rule, str):
            return rule in self._all_rules

        # If it's a rule, get the rule_id and check that
        elif isinstance(rule, Rule):
            return rule.rule_id in self._all_rules

        # Otherwise just return False
        return False

    def __iter__(self):
        '''
        Start the enumeration
        '''
        self._iter = self._all_rules.values().__iter__()
        return self

    def __next__(self):
        '''
        Provide the next rule in the enumeration

        Example
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> for rule in txt:
        ...     rule
        ...     break
        ...
        Rule(rule_id:1:24511, action:alert, state:ENABLED)
        '''
        next_rule = self._iter.__next__()
        return next_rule

    def __getitem__(self, rule_id):
        '''
        Allows for getting rules using: rules['1:2001']

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> txt['1:10018']
        Rule(rule_id:1:10018, action:alert, state:ENABLED)
        '''
        rule = self._all_rules[rule_id]
        return rule

    def get(self, rule_id, default=None):
        '''
        Return the rule with a given ID (or default instead)

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> txt.get('1:1', 'nope')
        'nope'
        >>> txt.get('1:10018')
        Rule(rule_id:1:10018, action:alert, state:ENABLED)
        '''

        # Get the rule
        res = default
        if rule_id in self._all_rules:
            res = self._all_rules[rule_id]
        return res

    def load_file(self, rules_file):
        '''
        Load a rules file

        Example:
        >>> txt = Rules()
        >>> txt
        Rules(loaded:0, enabled:0, disabled:0)
        >>>
        >>> txt.load_file('../rules/snort3-netbios.rules')
        >>> txt
        Rules(loaded:244, enabled:244, disabled:0)
        '''

        # We'll use a copy
        metadata = self.metadata.copy()

        # Work through the policy file
        with open(rules_file, 'r') as fh:

            # Save the filename bits to the metadata
            metadata['file_path'] = rules_file
            metadata['file_name'] = os.path.basename(rules_file)

            for line_num, line in enumerate(fh.readlines(), 1):

                # Strip the line
                line = line.strip()

                # Skip when we hit obvious non-rules (or pulled ones)
                if not line:
                    continue
                elif 'sid:' not in line:
                    continue
                elif '(' not in line and ')' not in line:
                    continue
                elif line.startswith('###### PULLED BY '):
                    continue

                # Attempt to parse the line as a rule
                try:
                    new_rule = Rule(line, **metadata)
                except ValueError as e:
                    log.verbose(f'{rules_file}:{line_num} - {e}')
                    continue

                # If the rule is already present, we want to keep
                # the one with the higher rev
                if new_rule.rule_id in self._all_rules:
                    current_rule = self[new_rule.rule_id]

                    # If the current rule has a later or same rev, move on
                    if current_rule.rev >= new_rule.rev:
                        log.verbose(f'{rules_file}:{line_num} - Duplicate rule_id with same/earlier rev; skipping')
                        continue

                # Save the rule to cache
                self._all_rules[new_rule.rule_id] = new_rule

    def write_file(self, rules_file, include_disabled=False, header=None):
        '''
        Write the rules to a file
        Optionally includes the disabled rules (commented out) and a header

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> txt.write_file('pulledpork.rules', include_disabled=True)
        '''

        # Open the file for writing
        with open(rules_file, 'w') as fh:

            # Write a file header?
            if header is not None:
                fh.write(f'{header}\n')

            # Work through all the rules
            for rule in self._all_rules.values():

                # If the rule is enabled
                if rule.state:
                    fh.write(f'{rule.text}\n')

                # Else iif the rule is disabled AND we're including the writing of them...
                elif not rule.state and include_disabled:
                    fh.write(f'# {rule.text}\n')

    def copy(self, rule_state=None):
        '''
        Create a copy of the Rules object

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> new = txt.copy()
        >>> new
        Rules(loaded:41987, enabled:41987, disabled:0)
        '''

        # Setup our new instance
        new_rules = Rules()

        # Copy the metadata over
        new_rules.metadata = self.metadata.copy()

        # Copy over the rules cache
        for rule_id, rule in self._all_rules.items():
            new_rules._all_rules[rule_id] = rule.copy()

        # Return the new Rules object
        return new_rules

    def apply_policy(self, policy):
        '''
        Apply the Policy to this rules object

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> pols = Policies('../rules')
        >>> pols['balanced']
        Policy(name:balanced, rules:8579)
        >>>
        >>> txt.apply_policy(pols['balanced'])
        >>> txt
        Rules(loaded:41987, enabled:8579, disabled:33408)
        '''

        # Wut?
        if not isinstance(policy, Policy):
            raise ValueError(f'Not a recognized Policy object:  {policy}')

        # Work through the rules
        # Toggle rule state based on the policy
        for rule_id, rule in self._all_rules.items():
            policy_rule = policy.rules.get(rule_id)
            if policy_rule:
                rule.state = policy_rule['state']
            else:
                rule.state = False

    def from_policy(self, policy):
        '''
        Create a new Rules object based on a given Policy

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> pols = Policies('../rules')
        >>> pols['balanced']
        Policy(name:balanced, rules:8579)
        >>>
        >>> new = txt.from_policy(pols['balanced'])
        >>> new
        Rules(loaded:41987, enabled:8579, disabled:33408)
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        '''

        # Setup our new instance and apply the policy
        new_rules = self.copy()
        new_rules.apply_policy(policy)

        # Return the new Rules object
        return new_rules

    def modify(self, rule_ids, state=None, action=None, ignore_missing=True):
        '''
        Update the state of the provided rule IDs

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> txt.modify('1:10018', state=False)
        >>> txt
        Rules(loaded:41987, enabled:41986, disabled:1)
        >>> txt.modify(['1:10017', '1:2002'], state=False)
        >>> txt
        Rules(loaded:41987, enabled:41984, disabled:3)
        >>> txt.modify('1:10018', state=True)
        >>> txt
        Rules(loaded:41987, enabled:41985, disabled:2)
        '''

        # Ensure we have something to modify
        if state is None and action is None:
            raise ValueError('No rule modifications to make; state or action required')

        # If rule_ids is a string, make it a list
        if isinstance(rule_ids, str):
            rule_ids = [rule_ids]

        # Work through the rule IDs
        for rule_id in rule_ids:

            # Missing?
            if rule_id not in self._all_rules:
                if not ignore_missing:
                    raise ValueError(f'Missing rule ID {rule_id} to modify')
                continue

            # Get the rule and update it
            rule = self._all_rules[rule_id]
            if state is not None:
                rule.state = state
            if action is not None:
                rule.action = action

    def modify_by_regex(self, regex_pattern, state=None, action=None):
        '''
        Update the state of the rules based on a regex pattern

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> txt.modify_by_regex('test', state=False)
        >>> txt
        Rules(loaded:41987, enabled:38345, disabled:3642)
        '''

        # Ensure we have something to modify
        if state is None and action is None:
            raise ValueError('No rule modifications to make; state or action required')

        # If it's a string, compile it
        if isinstance(regex_pattern, str):
            regex_pattern = re.compile(regex_pattern)
        elif not isinstance(regex_pattern, re.Pattern):
            raise ValueError('Provided regex pattern must be a str or re.Pattern')

        # Work through the rules
        for rule in self._all_rules.values():

            # Is the rule a match?
            if regex_pattern.search(rule.text):

                # Update the rule
                if state is not None:
                    rule.state = state
                if action is not None:
                    rule.action = action

    def extend(self, other_rules):
        '''
        Extend the current Rules object to include another Rules object

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> all = Rules()
        >>> all
        Rules(loaded:0, enabled:0, disabled:0)
        >>> all.extend(txt)
        >>> all
        Rules(loaded:41987, enabled:41987, disabled:0)
        '''

        # Wut?
        if not isinstance(other_rules, Rules):
            raise ValueError(f'Not a recognized Rules object:  {other_rules}')

        # Work through the rules
        for new_rule in other_rules:

            # If the rule is already present, we want to keep
            # the one with the higher rev
            if new_rule.rule_id in self._all_rules:
                current_rule = self[new_rule.rule_id]

                # If the current rule has a later or same rev, move on
                if current_rule.rev >= new_rule.rev:
                    log.verbose('Duplicate rule_id with same/earlier rev; skipping')
                    continue

            # Save the rule to cache
            self._all_rules[new_rule.rule_id] = new_rule

    def policy_from_state(self, name='rules-state'):
        '''
        Return a Policy object based on the state of the rules

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> pol = txt.policy_from_state()
        >>> pol
        Policy(name:rules-state, rules:41987)
        '''

        # Setup the new policy
        new_policy = Policy(name)

        # Work through the rules
        for rule in self._all_rules.values():

            # Update the policy with the rule state
            new_policy.update_rule(rule.gid, rule.sid, rule.action, rule.state)

        # Return the policy
        return new_policy


################################################################################
# Policy - A Rule policy
################################################################################

class Policy(object):

    def __init__(self, name, policy_file=None):
        '''
        Setup a new policy, loading a policy file if provided

        Example:
        >>> pol = Policy('custom')
        >>> pol
        Policy(name:custom, rules:0)
        >>> pol = Policy('balanced', '../rules/rulestates-balanced-ips.states')
        >>> pol
        Policy(name:balanced, rules:8579)
        '''

        # No rules to start
        self.name = name
        self.rules = {}

        # If we were given a policy file, attempt to load it
        if policy_file is not None:
            self.load_file(policy_file)

    def __repr__(self):
        return f'Policy(name:{self.name}, rules:{len(self.rules)})'

    def __len__(self):
        '''
        Return the number of rules in the policy

        Example:
        >>> pol = Policy('balanced', '../rules/rulestates-balanced-ips.states')
        >>> pol
        Policy(name:balanced, rules:8579)
        >>>
        >>> len(pol)
        8579
        '''
        return len(self.rules)

    def __contains__(self, rule):
        '''
        Return whether a rule is in the policy

        Example:
        >>> pol = Policy('balanced', '../rules/rulestates-balanced-ips.states')
        >>> pol
        Policy(name:balanced, rules:8579)
        >>>
        >>> '1:11835' in pol
        True
        '''

        # If it's a string, easy
        if isinstance(rule, str):
            return rule in self.rules

        # If it's a rule, get the rule_id and check that
        elif isinstance(rule, Rule):
            return rule.rule_id in self.rules

        # Otherwise just return False
        return False

    def update_rule(self, gid, sid, action='alert', state=True):
        '''
        Update, or add, a rule in this policy

        Example:
        >>> pol = Policy('custom')
        >>> pol
        Policy(name:custom, rules:0)
        >>> pol.update_rule(1, 2000)
        >>> pol
        Policy(name:custom, rules:1)
        '''

        # Compose the rule ID
        rule_id = f'{gid}:{sid}'

        # Save the rule to the dict
        self.rules[rule_id] = {
            'gid': gid,
            'sid': sid,
            'action': action,
            'state': state
        }

    def load_file(self, policy_file):
        '''
        Load a policy file

        Example:
        >>> pol = Policy('custom')
        >>> pol
        Policy(name:custom, rules:0)
        >>> pol.load_file('../rules/rulestates-balanced-ips.states')
        >>> pol
        Policy(name:custom, rules:8579)
        '''

        # Work through the policy file
        with open(policy_file, 'r') as fh:
            for line in fh.readlines():

                # Strip the line
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Not what we expected for a policy rule?
                if 'gid:' not in line and 'sid:' not in line:
                    continue

                # Use regex to parse the bits
                rule_parts = POLICY_RULE_REGEX.match(line)

                # If not a rule, move on
                if rule_parts is None:
                    continue

                # Save the bits (helps with reading the code)
                gid = rule_parts[2]
                sid = rule_parts[3]
                action = rule_parts[1]
                state = rule_parts[4] == 'enable'  # This should always be true

                # Save the rule
                self.update_rule(gid, sid, action, state)

    def copy(self):
        '''
        Create a copy of the Policy object

        Example:
        >>> pol = Policy('balanced', '../rules/rulestates-balanced-ips.states')
        >>> pol
        Policy(name:balanced, rules:8579)
        >>>
        >>> new = pol.copy()
        >>> new
        Policy(name:balanced, rules:8579)
        '''

        # Setup our new instance
        new_policy = Policy(self.name)

        # Copy over the rules
        new_policy.rules = self.rules.copy()

        # Return the new Rules object
        return new_policy

    def extend(self, other_policy):
        '''
        Extend the current Policy object to include another Policy

        Example:
        >>> pol = Policy('custom')
        >>> pol
        Policy(name:custom, rules:0)
        >>> pol2 = Policy('balanced', '../rules/rulestates-balanced-ips.states')
        >>> pol2
        Policy(name:balanced, rules:8579)
        >>>
        >>> pol.extend(pol2)
        >>> pol
        Policy(name:custom, rules:8579)
        '''

        # Wut?
        if not isinstance(other_policy, Policy):
            raise ValueError(f'Not a recognized Policy object:  {other_policy}')

        # Update the rules in this policy from the other
        self.rules.update(other_policy.rules)

    def write_file(self, policy_file, header=None):
        '''
        Write a single policy to a states file
        '''

        # Open the file for writing
        with open(policy_file, 'w') as fh:

            # Write a file header?
            if header is not None:
                fh.write(f'{header}\n')

            # Work through all the rules in the policy
            for rule in self.rules.values():

                # Only enabled rules should be written to the file
                if not rule['state']:
                    continue

                # Write the policy line
                fh.write(f'{rule["action"]} (gid:{rule["gid"]}; sid:{rule["sid"]}; enable)\n')


################################################################################
# Policies - A collection of Policy objects
################################################################################

class Policies(object):

    POLICY_MAP = {
        # filename: policy_name
        'rulestates-no-rules-active.states': 'none',
        'rulestates-connectivity-ips.states': 'connectivity',
        'rulestates-balanced-ips.states': 'balanced',
        'rulestates-max-detect-ips.states': 'max-detect',
        'rulestates-security-ips.states': 'security'
    }

    def __init__(self, rules_path=None):
        '''
        Load all the policies from the given rules path

        Example:
        >>> pols = Policies()
        >>> pols
        Policies(loaded:0, names:[])
        >>>
        >>> pols = Policies('../rules')
        >>> pols
        Policies(loaded:5, names:[max-detect, balanced, security, connectivity, none])
        '''

        # Setup the policy cache
        self._policies = {}

        # No rules to process?
        if rules_path is None:
            return

        # Is source a directory?
        if os.path.isdir(rules_path):

            # Work through the files in the given path
            for file in os.scandir(rules_path):

                # Attempt to identify policy files, otherwise move on
                try:
                    policy_name = self.POLICY_MAP[file.name]
                except KeyError:
                    continue

                # Load the policy
                self._policies[policy_name] = Policy(policy_name, file.path)

        # Is it a fiie?
        elif os.path.isfile(rules_path):

            # Get the file name only for the map
            base_filename = os.path.basename(rules_path)

            # Attempt to identify policy files, otherwise move on
            try:
                policy_name = self.POLICY_MAP[base_filename]
            except KeyError:
                raise ValueError(f'Unknown policy source:  {rules_path}')

            # Load the policy
            self._policies[policy_name] = Policy(policy_name, rules_path)

        # Not present, raise an exception
        else:
            raise FileNotFoundError(rules_path)

    def __repr__(self):
        return f'Policies(loaded:{len(self._policies)}, names:[{", ".join(self._policies.keys())}])'

    def __len__(self):
        '''
        Return the number of loaded policies

        Example:
        >>> pols = Policies('../rules')
        >>> pols
        Policies(loaded:5, names:[max-detect, balanced, security, connectivity, none])
        >>>
        >>> len(pols)
        5
        '''
        return len(self._policies)

    def __iter__(self):
        '''
        Start the enumeration
        '''
        self._iter = self._policies.values().__iter__()
        return self

    def __next__(self):
        '''
        Provide the next policy in the enumeration

        Example:

        >>> pols = Policies('../rules')
        >>> pols
        Policies(loaded:5, names:[max-detect, balanced, security, connectivity, none])
        >>>
        >>> for pol in pols:
        ...     pol
        ...
        Policy(name:max-detect, rules:33763)
        Policy(name:balanced, rules:8579)
        Policy(name:security, rules:15476)
        Policy(name:connectivity, rules:478)
        Policy(name:none, rules:0)
        '''
        next_policy = self._iter.__next__()
        return next_policy

    def __contains__(self, policy_name):
        '''
        Return whether a policy name is in the Policies object

        Example:
        >>> pols = Policies('../rules')
        >>> pols
        Policies(loaded:5, names:[max-detect, balanced, security, connectivity, none])
        >>>
        >>> 'balanced' in pols
        True
        '''
        return policy_name in self._policies

    def __getitem__(self, policy_name):
        '''
        Allows for gets using: policies['none']

        Example:
        >>> pols = Policies('../rules')
        >>> pols
        Policies(loaded:5, names:[max-detect, balanced, security, connectivity, none])
        >>>
        >>> pols['balanced']
        Policy(name:balanced, rules:8579)
        '''
        return self._policies[policy_name]

    def get(self, policy_name, default=None):
        '''
        Return the policy with a given name (or default instead)

        Example:
        >>> pols = Policies('../rules')
        >>> pols
        Policies(loaded:5, names:[max-detect, balanced, security, connectivity, none])
        >>>
        >>> pols.get('xxx', 'nope')
        'nope'
        >>> pols.get('balanced')
        Policy(name:balanced, rules:8579)
        '''

        # Get the rule
        res = default
        if policy_name in self._policies:
            res = self._policies[policy_name]
        return res

    def copy(self):
        '''
        Create a copy of this Policies object

        Example:
        >>> pols = Policies('../rules')
        >>> pols
        Policies(loaded:5, names:[max-detect, balanced, security, connectivity, none])
        >>>
        >>> new = pols.copy()
        >>> new
        Policies(loaded:5, names:[max-detect, balanced, security, connectivity, none])
        '''

        # Setup our new instance
        new_policies = Policies()

        # Copy over the policies
        for policy_name, policy in self._policies.items():
            new_policies._policies[policy_name] = policy.copy()

        # Return the new Rules object
        return new_policies

    def extend(self, other_thing):
        '''
        Extend the current Policies object to include another Policy or Policies object

        Example:
        >>> pols = Policies()
        >>> pols
        Policies(loaded:0, names:[])
        >>> pols2 = Policies('../rules')
        >>> pols2
        Policies(loaded:5, names:[max-detect, balanced, security, connectivity, none])
        >>>
        >>> pols.extend(pols2)
        >>> pols
        Policies(loaded:5, names:[max-detect, balanced, security, connectivity, none])
        '''

        # If it's a Policies object we'll work to combine them
        if isinstance(other_thing, Policies):

            # Work through the policies
            for policy_name, policy in other_thing._policies.items():

                # If we don't have the policy, add it
                if policy_name not in self._policies:
                    self._policies[policy_name] = policy

                # If we do have the policy, update that policy
                else:
                    self._policies[policy_name].rules.update(policy.rules)

        # If it's a policy object we'll add it, or extend it if it exists
        elif isinstance(other_thing, Policy):

            # If we have a policy by that name, update the policy
            if other_thing.name in self._policies:
                self._policies[other_thing.name].rules.update(other_thing.rules)

            # Doesn't exist, add it
            else:
                self._policies[other_thing.name] = other_thing

        # Wut?
        else:
            raise ValueError(f'Not a recognized Policy or Polcies object:  {other_thing}')


################################################################################
# RulesArchive - Helper for loads, saving, and extracting rules archives
################################################################################

class RulesArchive(object):

    def __init__(self, ruleset=None, filename=None, url=None, oinkcode=None):
        '''
        Setup the new rules archive
        '''

        # Validate only one set
        if filename and url:
            raise ValueError('Only one -- `filename` or `url` -- may be used at once')

        # Setup the archive
        self._data = None
        self._ruleset = ruleset
        self.source = None
        self.filename = None
        self.extracted_path = None

        # Load the archive if we have one
        if filename:
            self.load_file(filename)
        if url:
            self.load_url(url, oinkcode)

    def __repr__(self):
        return f'RulesArchive(ruleset:{self.ruleset})'

    @property
    def md5(self):
        '''
        Return the MD5 of the loaded rules archive
        '''

        # Validate we have the archive data
        if not self._data:
            raise ValueError('Rules archive has not been loaded')

        # Return the MD5 hex string
        return hashlib.md5(self._data).hexdigest()

    @property
    def ruleset(self):
        '''
        Attempt to identify the ruleset archive, or return
        what we already have
        '''

        # If we haven't yet determined a ruleset, find one
        if not self._ruleset:

            # Nothing loaded yet
            if not self.filename:
                return RulesetTypes.UNKNOWN

            # Try the easy stuff first
            elif self.filename == 'snort3-community-rules.tar.gz':
                self._ruleset = RulesetTypes.COMMUNITY
            elif self.filename.startswith('snortrules-snapshot-'):
                self._ruleset = RulesetTypes.REGISTERED
            elif self.filename == 'Talos_LightSPD.tar.gz':
                self._ruleset = RulesetTypes.LIGHTSPD

            # Need the ruleset to be downloaded to perform additional checks
            elif not self._data:
                return RulesetTypes.UNKNOWN

            # Harder tries
            else:

                # Get the filename list from the downloaded file
                tarobj = io.BytesIO(self._data)
                with tarfile.open(fileobj=tarobj) as fh:
                    filenames = fh.getnames()

                    # These checks kinda suck, but...
                    if all(x in filenames for x in RULESET_COMMUNITY_FILE_CHECKS):
                        self._ruleset = RulesetTypes.COMMUNITY
                    elif all(x in filenames for x in RULESET_REGISTERED_FILE_CHECKS):
                        self._ruleset = RulesetTypes.REGISTERED
                    elif all(x in filenames for x in RULESET_REGISTERED_FILE_CHECKS):
                        self._ruleset = RulesetTypes.LIGHTSPD

                    # Have no idea
                    else:
                        self._ruleset = RulesetTypes.UNKNOWN

        # Return the ruleset
        return self._ruleset

    def load_file(self, rules_path):
        '''
        Load a archive file
        '''

        # Save the bits
        self.source = rules_path
        self.filename = os.path.basename(rules_path)

        # Open and read the file into _data
        with open(rules_path, 'rb') as fh:
            self._data = fh.read()

    def load_url(self, rules_url, oinkcode=None):
        '''
        Load the rules file from the URL
        '''

        # Save the bits
        self.source = rules_url
        self.filename = os.path.basename(rules_url)

        # Compose the parameters, adding oinkcode if requested
        params = {}
        if oinkcode is not None:
            params['oinkcode'] = oinkcode

        # Download the URL, and check response status?
        resp = requests.get(rules_url, params=params)
        resp.raise_for_status()

        # Save the downloaded contents
        self._data = resp.content

    def write_file(self, target_path, filename=None):
        '''
        Save the archive to target path
        '''

        # Validate we have the archive data
        if not self._data:
            raise ValueError('Rules archive has not been loaded')

        # If no filename is provided, use the URL filename
        filename = filename or self.filename
        target_file = os.path.join(target_path, filename)

        # Write the downloaded data to a file on disk
        with open(target_file, 'wb') as fh:
            fh.write(self._data)

        # Return the written filename
        return target_file

    def extract(self, target_path):
        '''
        Extract the rules archive to a target path
        '''

        # Validate we have the archive data
        if not self._data:
            raise ValueError('Rules archive has not been loaded')

        # Setup a fileobj from the downloaded data
        tarobj = io.BytesIO(self._data)

        # Extract the data to disk
        with tarfile.open(fileobj=tarobj) as fh:
            fh.extractall(target_path)

        # Save the path where it was extracted
        self.extracted_path = target_path
