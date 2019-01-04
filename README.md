# zabbix_host_webscenario
Ansible module for managing host web scenario in zabbix

Tested on:

zabbix 4.0.2 and ansible 2.7.5


## Module documentation
```yaml
module: zabbix_host_webscenario
short_description: Zabbix host webscenarios creates/updates/deletes
description:
   - Create, update or delete Zabbix host web scenarios
version_added: "2.7"
author:
  - Hampus Lundqvist
requirements:
    - "python >= 2.6"
    - zabbix-api
options:
    host_name:
        description:
            - Name of the host for the web scenario.
       required: true
    name:
        description:
            - Web scenario name
            - Name is a unique identifier used and cannot be updated using this module.
        required: true
    agent:
        description:
            - Http agent used when performing the steps.
        required: false
    application_name:
        description:
            - Application to assign the web scenario to.
            - Application name must exist or module will fail.
        required: false
    authentication:
        description:
            - Authentication type
            - 0 for none, 1 for basic http auth, 2 for ntlm.
        required: false
        choices: [ 0, 1, 2 ]
        default: '0'
    delay:
        description:
            - The update interval
        required: false
    http_password:
        description:
            - Password for authentication
        required: false
    http_proxy:
        description:
            - Proxy to be used by web scenario
        required: false
    http_user:
        description:
            - User name for authentication
        required: false
    retries:
        description:
            - Number of times to retry each step before failing
        default: 1
    ssl_cert_file:
        description:
            - Name of ssl certificate file to be used
        required: false
    ssl_key_file:
        description:
            - Name of ssl key file to be used
        required: false
    ssl_key_password:
        description:
            - Password for the ssl key file
        required: false
    status:
        description:
            - Monitoring status of the web scenario.
        choices: ['enabled', 'disabled']
        default: 'enabled'
    verify_host:
        description:
            - Whether to verify that the host name in the SSL certificate matches the one used in the web scenario
            - 0 skip, 1 verify host
        default: 0
    verify_peer:
        description:
            - Whether to verify the SSL certificate of the web server.
            - 0 skip, 1 verify peer
        default: 0
    steps:
        description:
            - All the scenario steps in a list to be added/updated
            - It will remove any steps listed when it is used
            - when used keep in mind that we need to escape the step number called no, as 'no'
                otherwise ansible will resolve no to False and the module will fail
            - Additional documentation for step parameters see Zabbix api reference httptest/object,
                especially sections Scenario step aswell as HTTP Field variables
        required: False
    state:
        description:
            - State of the webscenario.
            - On C(present), it will create if webscenario does not exist or update the webscenario if the associated data is different.
            - On C(absent) will remove a webscenario if it exists.
        required: false
        choices: ['present', 'absent']
        default: "present"
    force:
        description:
            - Only updates an existing web scenario if set to C(yes).
        default: 'no'
        type: bool
extends_documentation_fragment:
    - zabbix
```
