# bolt_log4j

A bolt plan which make use of Google's [log4jscanner][1] to allow scanning of Windows and Linux hosts at scale for the [log4shell][2] vulnerability.

## Table of Contents

1. [Description](#description)
1. [Setup - The basics of getting started with bolt_log4j](#setup)
    * [What bolt_log4j affects](#what-bolt_log4j-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with bolt_log4j](#beginning-with-bolt_log4j)
1. [Usage - Configuration options and additional functionality](#usage)
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
2. Create

## Usage

Include usage examples for common use cases in the **Usage** section. Show your
users how to use your module to solve problems, and be sure to include code
examples. Include three to five examples of the most important or common tasks a
user can accomplish with your module. Show users how to accomplish more complex
tasks that involve different types, classes, and functions working in tandem.

## Reference

This section is deprecated. Instead, add reference information to your code as
Puppet Strings comments, and then use Strings to generate a REFERENCE.md in your
module. For details on how to add code comments and generate documentation with
Strings, see the [Puppet Strings documentation][2] and [style guide][3].

If you aren't ready to use Strings yet, manually create a REFERENCE.md in the
root of your module directory and list out each of your module's classes,
defined types, facts, functions, Puppet tasks, task plans, and resource types
and providers, along with the parameters for each.

For each element (class, defined type, function, and so on), list:

* The data type, if applicable.
* A description of what the element does.
* Valid values, if the data type doesn't make it obvious.
* Default value, if any.

For example:

```
### `pet::cat`

#### Parameters

##### `meow`

Enables vocalization in your cat. Valid options: 'string'.

Default: 'medium-loud'.
```

## Limitations

In the Limitations section, list any incompatibilities, known issues, or other
warnings.

## Development

In the Development section, tell other users the ground rules for contributing
to your project and how they should submit their work.

## Release Notes/Contributors/Etc. **Optional**

If you aren't using changelog, put your release notes here (though you should
consider using changelog). You can also add any additional sections you feel are
necessary or important to include here. Please use the `##` header.

[1]: https://github.com/google/log4jscanner
[2]: https://en.wikipedia.org/wiki/Log4Shell
[3]: https://www.puppet.com/docs/bolt/latest/bolt_installing