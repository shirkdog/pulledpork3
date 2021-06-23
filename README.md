PulledPork3
===========

Pulled Pork for Snort3 rule management (Everything is better smoked)

Find us on Libera.Chat (IRC) [`#pulledpork`](https://libera.chat/guides/connect)

Copyright (C) 2021 Noah Dietrich and the PulledPork Team!

## Warning

This is beta software, released for testing purposes and to solicit feedback.
Use at your own risk, and please report bugs back to the PulledPork team through github.
Include as much information as possible with bug and feature reports, including your configuraiton file *(remove your oinkcode)*, output, and expected results.

## Installation and Requirements

PulledPork requires Python 3 with the standard libraries.
extract the pulledpork.conf and pulledpork.py file to a suitable location (/usr/local/bin/pulledpork/ or c:\program files\PulledPork).

PulledPork3 has been tested on Windows, Linux and other Unix-LIKE/BSD systems.

## Configuration

PulledPork relies on a configuration file and command line arugments to run. Command line arguments take precidence when thre is a conflict between the two.  A sample configuraiton file is included (pulledpork.conf). See detailed configuration options below.

## Running PulledPork

To test that PulledPork runs correctly, just execute the following command to display the version and exit:
```
$ ./pulledpork.py -V
```

if that doesn't work, you may need to specify your python interpreter:
```
$ /usr/bin/python ./pulledpork.py -V
```

You can display all commmand line arguments:
```
$ ./pulledpork.py -h
```

You will need to supply the path to a configuration file when running PulledPork:
```
$ ./pulledpork.py -c etc/pulledpork.conf
```

The above command is how most people will want to run PulledPork, and is the the most common command. There are a number of additional command line arguments if you are trying troubleshooting PulledPork.

You can optionally increase or decrese the verbosity of the output:
```
|argument|result|
|--------|------|
|-v, --verbose  | Increase output verbosity
|-vv, --debug   | Really increase output verbosity
|-q, --quiet    | Only display warnings and errors
```

By default, PulledPork will exit on warnings. You can override this feature with the -i (--ignore-warn) argument.  Note that most warnings are fairly serious and in most instances it's better that PulledPork exits rather than continues execution:
```
$ ./pulledpork.py -c pulledpork.conf -i
```

By defualt, PulledPork will delete the temporary working directory on exit. you can use the -k (--keep-temp-dir) argument to keep the directory on exit:
```
$ ./pulledpork.py -c pulledpork.conf -k
```

## Detailed Configuration Options

Make a copy of the included pulledpork.conf file, and work on that copy (in case you mess something up you can go back to the original when troubleshooting). The config file has major sections identified with [brackets], and key = value options in each major section.

### rulesets section

The [rulesets] section identifies which rulesets to download, as well as your Snort oinkcode (for the registered and LightSPD rulesets).  Set the value to 'true' for the rulesets you want to download.  Note: you probably only want one of the three Snort rulesets (since there is a lot of overlap).  if you're unsure which ruleset to use, the LightSPD ruleset is recomended.

### blocklist section

This section identifies which blocklists (lists of malicious IP addresses) to download. Set the ones you want to 'true'.
You need to specify the location to write the combined blocklist file (all downloaded blocklists will be combined into a single file).  For example:
```
block_list_path=/usr/local/etc/snort/rules/iplists/default.blocklist
```
or:
```
block_list_path=c:\snort\blocklist.txt
```

If you have other additional blocklists you want to download: you can add any number of blocklists, each identified with an unique key=value pair, where the key must start with "blocklist_", and be unique (blocklist_01=.., blocklist_02=..., ...), and the value must be the url of the blocklist. For example:
```
blocklist_01       = http://a.b.com/list.list
blocklist_02       = http://c.d.e.com/blocklist.list
```

### snort section

This section details optional information about your environment, and is not required in most instances. PulledPork needs to know the version of Snort you're running, and will try to do that automatically by checking the default path for the snort binary.  If for some reason PulledPork can't determine the version of snort, it will error out. You can provide the path to the snort binary using the `snort_path` option, or you can provide the version of snort using the `snort_version` option
the `snort_path` option is only needed if PulledPork can't determine the version

the `pid_path` option will allow pulledpork to reload Snort (not yet implemented).

### configuration section

This section is the most important to ensure all the downloaded ruleset files are being written correctly.

The `ips_policy` option is used to determine which rules in the registered and LightSPD rulesets to enable and disable to allow you to ballance security and functionality. The choices for this option are: *connectivity, balanced, security, max-detect,* and *none*.  The default (and recomended) is connectivity.  More informatoin [here](https://www.snort.org/faq/why-are-rules-commented-out-by-default).  

Snort3 can optionally use a *policy* file to enable and disable rules, and PulledPork can support this functionality.  The simple way of loading rules with snort3 is to simply include a rules file (ips.include = "snort.rules"). All rules in that snort.rules that aren't disabled (lines starting with the hash mark are disabled or comments) are loaded by snort.  However, you can write all rules to the snort.rules file without disabling any of them, and then you can load a policy file that enables and disables rules based on the GID:SID of the rule. This allows you to modify which rules are enabled/disabled on the fly, or by choosing different policy files when running Snort. This is more complex, but also much more flexible.

The `rule_mode` option is used to determine which of these two options to use. You can choose either *simple* or *policy*.  If you choose policy, you'll also need to specify the policy_path option as well.

To load the policy file...(TODO)

You must specify the `rule_path` to tell PulledPork to write the rules file (in both simple and policy modes).

the `local_rules` option lets you add your own rules files to the output, and you can include multiple files.  
If you're using the policy mode: then all local rules will be added in the snort.rules file, but will be enabled/disabled with entries the policy file (if the rule is disabled in your local.rules file, then it will be included in the snort.rules file without a hash mark, but will be disabled with an entry in the policy file).

.SO rules (documentation TODO)
    process_so_rules = true
    sorule_path=c:\snort\rules\so_rules
    distro=ubuntu-x64

There are additional options in this section, read the example pulledpork.conf for details


