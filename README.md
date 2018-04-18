# IPAMagic
> Python Module for Ansible

Manage IPAM and DNS via Web API

[![GitHub issues](https://img.shields.io/github/release/vipulkanade/ipamagic.svg)](https://github.com/vipulkanade/ipamagic/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
[![PyPI license](https://img.shields.io/pypi/l/ansicolortags.svg)](https://pypi.python.org/pypi/ansicolortags/)
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)

## Dependencies
- Python "requests" module is required
```
sudo pip install requests
```


| Options   |      Description      |  Required |
|----------|:-------------:|------:|
| server |  IP/URL | true |
| username | username with API privileges  |   true |
| password | password |    true |
| action | Action to perform |    true |
| host | Hostname variable to search, add or delete host object |    false |
| network | Network address |    false |
| address | IP Address |    false |
| addresses | IP Addresses |    false |
| attr_name | Extra Attribute name |    false |
| comment | This comment will be added when the module create any object |    false |
| api_version | Web API version |    false |
| attr_name | Extra Attribute name |    false |

