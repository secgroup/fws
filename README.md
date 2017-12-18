FireWall Synthesizer
=========
Language-independent Synthesis of Firewall Policies

### Requirements
* `Z3` theorem prover from Microsoft Research, version >= `4.4.0`
* `GHC` the Glasgow Haskell Compiler, version >= `7.10.3`
* `cabal-install` command line interface to Cabal and Hackage, version >= `1.22.6.0`
* `python` Python language interpreter, version == 2.7.*
* `virtualenv` tool to create isolated Python environments, version >= 15.1.0
* `pip` tool for installing Python packages, version >= 9.0.1

### Installation
Install the required packages
```
sudo apt install z3 libz3-dev ghc cabal-install python-pip python-virtualenv
```
Update cabal package list and make the virtual environment
```
cabal update
make
```
The libraries and executables are installed in the `venv` python virtual environment:
```
source venv/bin/activate
```

the executable is `fws`.

### Usage
```
usage: fws [-h]
           FRONTEND {synthesis,implication,equivalence,diff,convert,query} ...

FireWall Synthesizer - Language-independent Synthesis of Firewall Policies

positional arguments:
  FRONTEND              Frontend name or diagram file (frontends: cisco, ipfw,
                        iptables, pf)
  {synthesis,implication,equivalence,diff,convert,query}
                        Subcommands
    synthesis           Syntesize a specification
    implication         Check for policy implication
    equivalence         Check for policy equivalence
    diff                Synthesize difference between two firewalls
    convert             Convert a configuration to the generic language
    query               Display the rules that affect the selected packets

optional arguments:
  -h, --help            show this help message and exit
```

### Usage Examples
#### Policy Analysis
  * Synthesizing the entire specification
    ```
    $ fws iptables synthesis -i examples/policies/interfaces -f examples/policies/iptables.rules
    ```
  * Checking the equivalence of two policies
    ```
    $ fws iptables equivalence -i examples/policies/interfaces \
                               -f examples/policies/iptables.rules \
                               -s examples/policies-update/iptables_new_rule.rules
    ```
  * Getting *related rules*
    ```
    $ fws iptables query -i examples/policies/interfaces \
                         -f examples/policies-update/iptables_new_rule.rules \
                         -q "srcIp == 10.0.1.22 && protocol == tcp && dstPort == 80 && state == NEW"
    ```
  * Getting the difference for the connections to port `80`
    ```
    $ fws iptables diff -i examples/policies/interfaces \
                        -f examples/policies/iptables.rules \
                        -s examples/policies-update/iptables_new_rule_correct.rules \
                        -q "protocol == tcp && dstPort == 80" --forward
    ```

#### Policy Verification
The script `run_examples.sh` in the `examples` directory shows how the tool
can be used to verify the fulfillment of the requirements of the firewall and
to spot possible differences in the `iptables`, `ipfw` and `pf` configurations.
```
$ source venv/bin/activate
$ cd examples
$ ./run_examples.sh
```
#### Policy Equivalence
The script `check_equivalence.sh` in the `examples` directory shows how the equivalence
feature of the tool can be used to check whether two policies (for `iptables` and `ipfw`)
are equivalent for the requirements of the firewall.
```
$ source venv/bin/activate
$ cd examples
$ ./check_equivalence.sh
```

