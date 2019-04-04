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

### Usage Examples
#### Policy Analysis
  * Loading a policy
    ```
    $ fws
    FWS> ipt = load_policy(iptables, "examples/policies/iptables.rules", "examples/policies/interfaces_aliases.conf")
    ```
  * Synthesizing the entire specification
    ```
    FWS> synthesis(ipt)
    ```
  * Checking the equivalence of two policies
    ```
    FWS> ipt2 = load_policy(iptables, "examples/policies-update/iptables_new_rule.rules", "examples/policies/interfaces_aliases.conf")
    FWS> equivalence(ipt, ipt2)
    ```
  * Getting *related rules*
    ```
    FWS> related(ipt2) where srcIp = 10.0.1.22 and protocol = tcp and dstPort = 80 and state = NEW
    ```
  * Getting the difference for the connections to port `80`
    ```
    FWS> ipt3 =  load_policy(iptables, "examples/policies-update/iptables_new_rule_correct.rules", "examples/policies/interfaces_aliases.conf")
    FWS> diff(ipt, ipt3) in forward where protocol = tcp and dstPort = 80
    ```
  
  Each table can be projected to show only the columns you are interested in
  ```
  synthesis(ipt)
   project (srcIp, srcPort, dstIp, dstPort, protocol)
   in forward where
    ( (srcIp = lan0 and dstIp = lan1) or
      (srcIp = lan1 and dstIp = lan0) ) and state = NEW
  ```

  FWS can be used in non-iteractive mode giving it an fws script as the first command line argument
  ```
  $ fws script.fws
  ```

#### Policy Verification
The script `examples.fws` in the `examples` directory shows how the tool
can be used to verify the fulfillment of the requirements of the firewall and
to spot possible differences in the `iptables`, `ipfw` and `pf` configurations.
```
$ source venv/bin/activate
$ cd examples
$ fws examples.fws
```
#### Policy Equivalence
The script `equivalence.fws` in the `examples` directory shows how the equivalence
feature of the tool can be used to check whether two policies (for `iptables` and `ipfw`)
are equivalent for the requirements of the firewall.
```
$ source venv/bin/activate
$ cd examples
$ fws equivalence.fws
```
#### Query Examples
The script `real_world.fws` in the `examples` directory shows some query examples on real
policies.
```
$ source venv/bin/activate
$ cd examples
$ fws real_world.fws
```
