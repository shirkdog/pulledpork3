PulledPork3
===========

Pulled Pork for Snort3 rule management (Everything is better smoked)

Find us the Snort Discord [https://discord.gg/Sdgsg8MtQQ](https://discord.gg/Sdgsg8MtQQ) or on Libera.Chat (IRC) [`#pulledpork`](https://libera.chat/guides/connect) 

Copyright (C) 2021 Noah Dietrich, Colin Grady, Michael Shirk and the PulledPork Team!

## Warning

This is beta software, released for testing purposes and to solicit feedback.
Use at your own risk, and please report bugs back to the PulledPork team through [github](https://github.com/shirkdog/pulledpork3/issues/new/choose).  Include as much information as possible when submitting bug and feature reports, including your configuration file *(remove your oinkcode)*, output, and expected results.  Please make sure you are using the latest version of the PulledPork repo before submitting a bug.

## Installation and Requirements

PulledPork requires Python 3 with the (mostly) standard libraries.
Due to the active development of PulledPork, you should clone the latest version off of github to make sure you're working with the most recent code.
PulledPork3 has been tested on Windows, Linux and other Unix-LIKE/BSD systems.

## Configuration

PulledPork relies on a configuration file and command line arugments to run. Command line arguments take precidence when there is a conflict between the two.  A sample configuraiton file is included (pulledpork.conf). See detailed configuration options below.

## Installing and Running PulledPork
Clone the PulledPork3 repository and copy the necessary files to a suitable location (/usr/local/bin/pulledpork/ or c:\program files\PulledPork\).
```
git clone https://github.com/shirkdog/pulledpork3.git
cd pulledpork3

sudo mkdir /usr/local/etc/pulledpork/
sudo cp etc/pulledpork.conf /usr/local/etc/pulledpork/

sudo mkdir /usr/local/bin/pulledpork/
sudo cp pulledpork.py /usr/local/bin/pulledpork/
sudo cp -r lib/ /usr/local/bin/pulledpork/
```

To test that PulledPork runs correctly, just execute the following command to display the version and exit:
```
$ pulledpork.py -V
```

if that doesn't work, you may need to specify your python interpreter and/or the full path to the pulledpork.py script:
```
$ /usr/bin/python3 /usr/local/bin/pulledpork/pulledpork.py -V
```

You can display all commmand line arguments:
```
$ pulledpork.py -h
```

You will need to supply the path to a configuration file when running PulledPork:
```
$ pulledpork.py -c /usr/local/etc/pulledpork/pulledpork.conf
```

The above command is how most people will want to run PulledPork. There are a number of additional command line arguments if you are trying troubleshooting PulledPork.

You can optionally increase or decrese the verbosity of the output:

|argument|result|
|--------|------|
|`-v`, `--verbose`  | Increase output verbosity         |
|`-vv`, `--debug`   | Really increase output verbosity  |
|`-q`, `--quiet`    | Only display warnings and errors  |


By default, PulledPork will exit on warnings. You can override this feature with the `-i` (`--ignore-warn`) argument.  Note that most warnings are fairly serious and in most instances it's better that PulledPork exits rather than continues execution:
```
$ pulledpork.py -c pulledpork.conf -i
```

By defualt, PulledPork will delete the temporary working directory on exit. you can use the `-k` (`--keep-temp-dir`) argument to keep the directory on exit (helpful during troubleshooting):
```
$ ./pulledpork.py -c pulledpork.conf -k
```

## Detailed Configuration Options

Make a copy of the included pulledpork.conf file, and work on that copy (in case you mess something up you can go back to the original when troubleshooting). The pulledpork.conf file is similar to the original pulledpork configuration file, but is not the same.  The conf file is well-documented, and entries are enabled and disabled by commenting out the line with the hash (#) symbol

### rulesets 
PP3 curently supports downloading three rulesets from Snort/Talos: the *community* ruleset, the *registered* ruleset, and the *LightSPD* ruleset. You can specify which rulesets to download, as well as your Snort oinkcode (for the registered and LightSPD rulesets).  Set the value to 'true' for the rulesets you want to download.  Note: you probably only want one of the three Snort rulesets (since there is a lot of overlap).  If you're unsure which ruleset to use: the LightSPD ruleset is recomended. The registered and LightSPD rulesets require a free [Oinkcode](https://www.snort.org/oinkcodes) from Snort.

### Blocklists

This section identifies which blocklists (lists of malicious IP addresses) to download. Set the ones you want to 'true'.  You need to specify the location to write the combined blocklist file (all downloaded blocklists will be combined into a single file).  For example:
```
blocklist_path=/usr/local/etc/snort/rules/iplists/default.blocklist
```
or:
```
blocklist_path=c:\snort\blocklist.txt
```

If you have other additional blocklists you want to download: You can use the *blocklist_urls* option, uncomment it (remove the hash symbol from the front of the line) and include those blocklist(s), seperated by commas. For example:
```
blocklist_urls = http://a.b.com/list.list, https://x.y.z/bloclist.txt
```

### Snort Options

This section details optional information about your environment, and is not required in most instances. PulledPork needs to know the version of Snort you're running, and will try to do that automatically by checking the default path for the snort binary.  If for some reason PulledPork can't determine the version of Snort, it will error out. You can provide the path to the snort binary using the `snort_path` option, or you can explicity provide the version of snort using the `snort_version` option.  The `snort_path` option is only needed if PulledPork can't determine the version by looking for the snort binary on the system path.

the `pid_path` option will allow pulledpork to send the reload command to a running Snort3 process so that it loads the new rules. The pid file is written by Snort when running in Daemon mode or if you run snort with the '--create-pidfile' flag. The pid file is named 'snort.pid' and is saved in the logging directory (identified by the path passed to the `-l` flag when running snort). Note: this functionality is not yet supported on windows systems.

### Configuration Options

This section is the most important to ensure all the downloaded ruleset files are being written correctly.

The `ips_policy` option is used to determine which rules in the registered and LightSPD rulesets to enable and disable to allow you to ballance security and functionality. The choices for this option are: *connectivity*, *balanced*, *security*, *max-detect*, and *none*.  The default (and recomended) is connectivity.  More information [here](https://www.snort.org/faq/why-are-rules-commented-out-by-default).

Snort3 can optionally use a *policy* file to enable and disable rules dynamically, and PulledPork can support this functionality.  The simple way of loading rules with snort3 is to simply include a rules file (`ips.include = "snort.rules"` in your snort.lua file). All rules in that snort.rules file that aren't disabled (lines starting with the hash mark are disabled or comments) are loaded by snort.  However, you can write all rules to the snort.rules file without disabling any of them, and then you can load a policy file that enables and disables rules based on the GID:SID of the rule. This allows you to modify which rules are enabled/disabled on the fly, or by choosing different policy files when running Snort. This is more complex, but also much more flexible.

The `rule_mode` option is used to determine which of these two options to use. You can choose either *simple* or *policy*.  If you choose policy, you'll also need to specify the `policy_path` option as well.

To load the policy file...(TODO)

You must specify the `rule_path` to tell PulledPork to write the combined rules file (in both simple and policy modes).

the `local_rules` option lets you add your own rules files to the output, and you can include multiple files, seperated with commas.

If you're using the policy mode: then all local rules will be added in the snort.rules file, but will be enabled/disabled with entries the policy file (if the rule is disabled in your local.rules file, then it will be included in the snort.rules file without a hash mark, but will be disabled with an entry in the policy file).

the `ignored_files` option specifies which rule files should not be processed from the downloaded rulsets. The recomended default is `includes.rules, snort3-deleted.rules`, because those rules are not needed. Note that this setting also supports the old name `ignore` from the Perl PulledPork config.

## SO rules
SO rules are rules that are pre-compiled by Snort/Talos for a subset of platforms.  You specify the path where these compiled rule files should be written with the `sorule_path` option.  These rules are compiled for a specific set of platforms, and if your platform is supported, specify it with the `distro` option.  If your distro is not supported, comment this line out (in future releases, these so rules will be compiled manually for unsupported distros).

To load these so rules in snort, you must include that directory with the `--plugin-path` option.


There are additional options in the pulledpork.conf file, which are documented inline.


