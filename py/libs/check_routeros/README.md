check_routeros - Monitoring MikroTik devices
============================================

<p align="center">
  <a href="https://github.com/dinotools/monitoring-check_routeros/issues">
    <img alt="GitHub issues" src="https://img.shields.io/github/issues/dinotools/monitoring-check_routeros">
  </a>
  <a href="https://github.com/dinotools/monitoring-check_routeros/network">
    <img alt="GitHub forks" src="https://img.shields.io/github/forks/dinotools/monitoring-check_routeros">
  </a>
  <a href="https://github.com/dinotools/monitoring-check_routeros/stargazers">
    <img alt="GitHub stars" src="https://img.shields.io/github/stars/dinotools/monitoring-check_routeros">
  </a>
  <a href="https://github.com/DinoTools/monitoring-check_routeros/blob/main/LICENSE.md">
    <img alt="GitHub license" src="https://img.shields.io/github/license/dinotools/monitoring-check_routeros">
  </a>
  <a href="https://dinotools.github.io/monitoring-check_routeros">
    <img alt="Documentation" src="https://github.com/DinoTools/monitoring-check_routeros/actions/workflows/docs.yml/badge.svg">
  </a>
  <a href="https://exchange.icinga.com/dinotools/check_routeros">
    <img alt="Icinga Exchange" src="https://img.shields.io/badge/Icinga-Exchange-success">
  </a>
  <a href="https://pypi.org/project/routeros-check/">
    <img alt="PyPI - Downloads" src="https://img.shields.io/pypi/dm/routeros-check">
  </a>
  <a href="https://pypi.org/project/routeros-check/">
    <img alt="PyPI - Python Version" src="https://img.shields.io/pypi/pyversions/routeros-check">
  </a>
  <a href="https://pypi.org/project/routeros-check/">
    <img alt="PyPI - Format" src="https://img.shields.io/pypi/format/routeros-check">
  </a>
  <a href="https://pypi.org/project/routeros-check/">
    <img alt="PyPI - Status" src="https://img.shields.io/pypi/status/routeros-check">
  </a>
</p>

This is a monitoring plugin for [Icinga](https://icinga.com/), [Nagios](https://www.nagios.org/) and other compatible monitoring solutions to check [MikroTik](https://mikrotik.com/) devices running RouterOS.
It uses the API to fetch the required information.

Requirements
------------

- [Python](https://www.python.org/) >= 3.6
- Python Packages
    - [Click](https://pypi.org/project/click/)
    - [librouteros](https://pypi.org/project/librouteros/)
    - [nagiosplugin](https://pypi.org/project/nagiosplugin/)

Installation
------------

### PIP

If you want to use pip we recommend to use as virtualenv to install the dependencies.

```shell
pip install -r requirements.txt
```

Copy the script ```check_routeros.py``` and the directory ```routeros_check``` into your plugin directory.

### Debian/Ubuntu

Install the required packages

```shell
sudo apt-get install python3 python3-click python3-librouteros python3-nagiosplugin
```

Copy the script ```check_routeros.py``` and the directory ```routeros_check``` into your plugin directory.

### From PyPI

Install the package from PyPI.

```shell
pip install routeros-check
```

You should be able to run ```check_routeros``` after the package installation has been finished successfully.

> **Note**
> You have to update the command in the icinga CheckCommand example config.

Usage
-----

To get the latest help just run the following command.

```shell
./check_routeros.py --help
```

To get help for a subcommand just extend the previous command with the subcommand.
In the example below you will see how to get help for the ```tool.ping``` subcommand.

```shell
./check_routeros.py tool.ping --help
```

Subcommands/Checks
------------------

All commands require at least `api` and `read` permissions.
The permissions documented in the table are additional permissions.

| Subcommand             | Permissions | RouterOS | Description                                              |
|------------------------|-------------|----------|----------------------------------------------------------|
| interface              | -           | 6, 7     | Check interfaces                                         |
| interface.gre          | -           | 6        | Check GRE interfaces/tunnels                             |
| interface.vrrp         | -           | 6        | Check the state of an VRRP interface                     |
| routing.bgp.peers      | -           | 6        | Check if connection to BGP peers is established          |
| routing.ospf.neighbors | -           | 6        | Check if ospf neigbhors are reachable                    |
| system.clock           | -           | 6, 7     | Check the time from RouterOS against local time          |
| system.cpu             | -           | 6, 7     | Check the cpu load                                       |
| system.fan             | -           | 6, 7     | Check the fans                                           |
| system.memory          | -           | 6, 7     | Check system memory                                      |
| system.ntp.client      | -           | 6, 7     | Check the ntp client, offset and stratum                 |
| system.license         | -           | 6, 7     | Check the license level and deadline and renewal date    |
| system.power           | -           | 6, 7     | Check the overall power consumption if available         |
| system.psu             | -           | 6, 7     | Check the current, voltage and state of the power supply |
| system.temperature     | -           | 6, 7     | Check the cpu, system, board and more temperatures.      |
| system.update          | -           | 6, 7     | Check for updates                                        |
| system.uptime          | -           | 6, 7     | Check the uptime                                         |
| tool.ping              | test        | 6, 7     | Run the ping command on the device                       |

To get more information about the available subcommands/checks have a look at the [check_routeros Command Reference](https://dinotools.github.io/monitoring-check_routeros/cli/)

Resources
---------

- Git-Repository: https://github.com/DinoTools/monitoring-check_routeros
- Issues: https://github.com/DinoTools/monitoring-check_routeros/issues
- Documentation: https://dinotools.github.io/monitoring-check_routeros

License
-------

GPLv3+
