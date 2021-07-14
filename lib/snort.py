import os
import re
import logging


logger = logging.getLogger(__name__)


################################################################################
# Constants
################################################################################

# Rule regex patterns
RULE_REGEX = re.compile(r'^(#\s*)?((\w+).+\(.+sid:(\d+);.+\))\s*$')
RULE_GID_REGEX = re.compile(r'gid:(\d+);')
RULE_REV_REGEX = re.compile(r'rev:(\d+);')
POLICY_RULE_REGEX = re.compile(r'^(\w+) \(gid:(\d+?); sid:(\d+?); (\w+);\)$')


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
        Rule(rule_id:1:1000000001, state:ENABLED)
        '''

        # Use regex to parse the rule bits
        rule_parts = RULE_REGEX.match(rule)

        # If not a rule, move on
        if rule_parts is None:
            raise ValueError('Rule text was not able to be parsed')

        # Save the easy bits
        self._text = rule_parts[2]
        self.sid = rule_parts[4]
        self.action = rule_parts[3]
        self.state = rule_parts[1] is None
        self.metadata = metadata.copy()

        # Parse harder rule bits
        gid = RULE_GID_REGEX.search(rule)
        self.gid = gid[1] if gid is not None else '1'
        rev = RULE_REV_REGEX.search(rule)
        self.rev = rev[1] if rev is not None else '0'

    def __repr__(self):
        return f'Rule(rule_id:{self.rule_id}, state:{"ENABLED" if self.state else "DISABLED"})'

    @property
    def rule_id(self):
        '''
        Return the rule ID: GID:SID
        Do we want the rev also represented here?

        Example:
        >>> r = Rule('alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; content:"test"; sid:1000000001; rev:1;)')
        >>> r
        Rule(rule_id:1:1000000001, state:ENABLED)
        >>>
        >>> r.rule_id
        '1:1000000001'
        '''
        return f'{self.gid}:{self.sid}'

    @property
    def text(self):
        '''
        Return the enabled or disabled (commented-out) rule text

        Example:
        >>> r = Rule('alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; content:"test"; sid:1000000001; rev:1;)')
        >>> r
        Rule(rule_id:1:1000000001, state:ENABLED)
        >>>
        >>> r.text
        'alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; flow:established,to_server; content:"test"; sid:1000000001; rev:1;)'
        >>> r.state = False
        >>> r.text
        '# alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; flow:established,to_server; content:"test"; sid:1000000001; rev:1;)'
        '''
        if self.state:
            return self._text
        return f'# {self._text}'

    def copy(self):
        '''
        Return a new copy of the rule

        Example:
        >>> r = Rule('alert tcp $EXTERNAL_NET any -> $HOME_NET 1234 (msg:"This is a test"; content:"test"; sid:1000000001; rev:1;)')
        >>> r
        Rule(rule_id:1:1000000001, state:ENABLED)
        >>>
        >>> r2 = r.copy()
        >>> r2
        Rule(rule_id:1:1000000001, state:ENABLED)
        '''

        # Create a new copy of the rule and return it
        new_rule = Rule(self.text, **self.metadata)
        return new_rule


################################################################################
# Rules - A collection of Rule objects
################################################################################

class Rules(object):

    # The files we'll always ignore
    IGNORED_FILES = [
        'includes.rules',
        'snort3-deleted.rules'
    ]

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
        self._metadata = metadata

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
                if rules_file.name in self.IGNORED_FILES:
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

        # Wut?
        else:
            raise ValueError(f'Not a recognized rule: {rule}')

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
        Rule(rule_id:1:24511, state:ENABLED)
        '''
        next_rule = self._iter.__next__()
        return next_rule

    def __getitem__(self, rule_id):
        '''
        Allows for getting rules  using: rules['1:2001']

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> txt['1:10018']
        Rule(rule_id:1:10018, state:ENABLED)
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
        Rule(rule_id:1:10018, state:ENABLED)
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
        metadata = self._metadata.copy()

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
                    rule = Rule(line, **metadata)
                except ValueError as e:
                    logger.warning(f'{rules_file}:{line_num} - {e}')
                    continue

                # Already exists?
                if rule.rule_id in self._all_rules:
                    logger.warning(f'{rules_file}:{line_num} - {rule.rule_id} already exists; overwriting')

                # Save the rule to cache
                # Add/remove from the disabled index as required
                self._all_rules[rule.rule_id] = rule

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
                fh.write(header + '\n')

            # Write the rules

            # Work through all the rules
            for rule in self._all_rules.values():

                # If the rule is enabled
                if rule.state:
                    fh.write(f'{rule.text}\n')

                # Else iif the rule is disabled AND we're including the writing of them...
                elif not rule.state and include_disabled:
                    fh.write(f'{rule.text}\n')

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
        new_rules._metadata = self._metadata.copy()

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
            raise ValueError(f'Not a recognized Policy object: {policy}')

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
        Only the enabled rules in the policy will be included

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

        # Wut?
        if not isinstance(policy, Policy):
            raise ValueError(f'Not a recognized Policy object: {policy}')

        # Setup our new instance and apply the policy
        new_rules = self.copy()
        new_rules.apply_policy(policy)

        # Return the new Rules object
        return new_rules

    def modify(self, state, rule_ids, ignore_missing=True):
        '''
        Update the state of the provided rule IDs

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> txt.modify(False, '1:10018')
        >>> txt
        Rules(loaded:41987, enabled:41986, disabled:1)
        >>> txt.modify(False, ['1:10017', '1:2002'])
        >>> txt
        Rules(loaded:41987, enabled:41984, disabled:3)
        >>> txt.modify(True, '1:10018')
        >>> txt
        Rules(loaded:41987, enabled:41985, disabled:2)
        '''

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

            # Get the rule and update state
            rule = self._all_rules[rule_id]
            rule.state = state

    def modify_by_regex(self, state, regex_pattern):
        '''
        Update the state of the rules based on a regex pattern

        Example:
        >>> txt = Rules('../rules')
        >>> txt
        Rules(loaded:41987, enabled:41987, disabled:0)
        >>>
        >>> txt.modify_by_regex(False, 'test')
        >>> txt
        Rules(loaded:41987, enabled:38345, disabled:3642)
        '''

        # If it's a string, compile it
        if isinstance(regex_pattern, str):
            regex_pattern = re.compile(regex_pattern)
        elif not isinstance(regex_pattern, re.Pattern):
            raise ValueError('Provided regex pattern must be a str or re.Pattern')

        # Work through the rules
        for rule in self._all_rules.values():

            # Is the rule a match?
            if regex_pattern.search(rule._text):

                # Update the rule state
                rule.state = state

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
            raise ValueError(f'Not a recognized Rules object: {other_rules}')

        # Update the rules
        self._all_rules.update(other_rules._all_rules)


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

        # Wut?
        else:
            raise ValueError(f'Not a recognized rule: {rule}')

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
                if 'sid:' not in line:
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
                state = rule_parts[4] == 'enable'

                # Compose the rule ID
                rule_id = f'{gid}:{sid}'

                # Save the rule to the dict
                self.rules[rule_id] = {
                    'gid': gid,
                    'sid': sid,
                    'action': action,
                    'state': state
                }

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
            raise ValueError(f'Not a recognized Policy object: {other_policy}')

        # Update the rules in this policy from the other
        self.rules.update(other_policy.rules)


################################################################################
# Policy - A collection of Policy objects
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
                raise ValueError(f'Unknown policy source: {rules_path}')

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
            raise ValueError(f'Not a recognized Policy or Polcies object: {other_thing}')
