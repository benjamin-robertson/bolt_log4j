# bolt_log4j

A bolt plan which make use of Google's [log4jscanner][1] to allow scanning of Windows and Linux hosts at scale for the [log4shell][2] vulnerability.

## Table of Contents

1. [Description](#description)
1. [Setup - The basics of getting started with bolt_log4j](#setup)
    * [What bolt_log4j affects](#what-bolt_log4j-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with bolt_log4j](#beginning-with-bolt_log4j)
1. [Limitations - OS compatibility, etc.](#limitations)
1. [Development - Guide for contributing to the module](#development)

## Description

A bolt plan which make use of Google's [log4jscanner][1] to allow scanning of Windows and Linux hosts at scale for the [log4shell][2] vulnerability. 

## Setup

### What bolt_log4j affects

Bolt_log4j makes the following changes on systems.

* Installs Puppet agent binaries.
* Extracts the log4jscanner. By default it uses the following paths.
    * Windows: c:\
    * Linux: /tmp
* Executes the log4jscanner on the system. By default it scans the following paths
    * Windows: c:\
    * Linux /


### Setup Requirements

bolt_log4j requires [Puppet Bolt][3] to be installed on the scanning machine only.

Run bolt_log4j from a machine with access to the hosts you wish to scan. Port TCP/22 (SSH - Linux) and TCP/5985, TCP/5986 (WinRM - Windows) need to be open from the scanning machine to the target machines. Root or administrator credentials are also required for the target hosts. For Linux systems, a SSH key pair is recommended. 

### Beginning with bolt_log4j

1. Install [Puppet Bolt][3]
2. Create a directory for bolt project. `mkdir log4j_scanner`
3. Change into project directory. `cd log4j_scanner`
4. Init a new bolt project. `bolt project init`
5. Open the `bolt-project.yaml`. Update to include the bolt_log4j module as shown.
```
modules:
  - git: https://github.com/benjamin-robertson/bolt_log4j.git
    ref: 'main'
```
6. Install the modules by running `bolt module install`. Hint, if you need to force a refresh of modules you can run `bolt module install --force`
7. Confirm plan is install by running. `bolt plan show`. Confirm the `bolt_log4j::vuln` plan is showing.
8. Configure bolt [inventory.yaml][4] file as shown. You will most likely need to customize these options for your own environment, see [transport options][5].
```
---
config:
  transport: ssh
  ssh:
    user: ec2-user
    host-key-check: false
    native-ssh: true
    private-key: /home/ubuntu/.ssh/id_rsa.pem
    ssh-command: /usr/bin/ssh
groups:
  - name: rhel
    targets:
      - ip-10-64-61-143.ap-southeast-2.compute.internal
      - ip-10-64-229-181.ap-southeast-2.compute.internal
  - name: ubuntu
    targets:
      - 10.64.41.234
      - 10.64.214.252
      - 10.64.117.212
    config:
      ssh:
        user: ubuntu
  - name: windows
    targets:
      - 10.64.149.16
    config:
      transport: winrm
      winrm:
        user: tempadmin
        password: <your_password>
        ssl: false
```
9. To confirm 

## Usage



## Limitations

In the Limitations section, list any incompatibilities, known issues, or other
warnings.

## Development

In the Development section, tell other users the ground rules for contributing
to your project and how they should submit their work.

[1]: https://github.com/google/log4jscanner
[2]: https://en.wikipedia.org/wiki/Log4Shell
[3]: https://www.puppet.com/docs/bolt/latest/bolt_installing
[4]: https://www.puppet.com/docs/bolt/latest/inventory_files
[5]: https://www.puppet.com/docs/bolt/latest/bolt_transports_reference