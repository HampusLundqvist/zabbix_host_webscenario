#!/usr/bin/python
# vim: expandtab ai ts=4 sw=4
# -*- coding: utf-8 -*-

# (c) 2013-2014, Epic Games, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
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
'''

EXAMPLES = '''
- name: Create a new webscenario or update an existing webscenario's value
  local_action:
    module: zabbix_host_webscenario
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    host_name: ExampleHost
    name: Example Webscenario
    http_proxy: "http://mywebproxy:3128"
    application_name: "Example Web Monitoring"
    steps:
      - name: Example HomePage
        url: "http://examplehost.org/index.php"
        'no': 1
        status_code: "200,201,301,302"
      - name: Example next
        url: "http://examplehost.org/next.php"
        'no': 2
        status_code: "200"
    state: present
'''

try:
    from zabbix_api import ZabbixAPI, ZabbixAPISubClass

    # Extend the ZabbixAPI
    # Since the zabbix-api python module too old (version 1.0, no higher version so far).
    class ZabbixAPIExtends(ZabbixAPI):
        def __init__(self, server, timeout, user, passwd, validate_certs, **kwargs):
            ZabbixAPI.__init__(self, server, timeout=timeout, user=user, passwd=passwd, validate_certs=validate_certs)

    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False

from ansible.module_utils.basic import AnsibleModule


class HostWebscenario(object):
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx

    # get host id by host name
    def get_host_id(self, host_name):
        try:
            host_list = self._zapi.host.get({'output': 'extend', 'filter': {'host': host_name}})
            if len(host_list) < 1:
                self._module.fail_json(msg="Host not found: %s" % host_name)
            else:
                host_id = host_list[0]['hostid']
                return host_id
        except Exception as e:
            self._module.fail_json(msg="Failed to get the host %s id: %s." % (host_name, e))

    # get application id by application name
    def get_application_id(self, application_name):
        try:
            application_list = self._zapi.application.get({'output': 'extend', 'filter': {'name': application_name }})
            if len(application_list) < 1:
                self._module.fail_json(msg="Application not found: %s" % application_name)
            else:
                application_id = application_list[0]['applicationid']
                return application_id
        except Exception as e:
            self._module.fail_json(msg="Failed to get the application %s id: %s." % (application_name, e))

    # get host webscenario
    def get_host_webscenario(self, name, host_id):
        try:
            host_webscenario_list = self._zapi.httptest.get(
                {"output": "extend", "selectSteps": "extend", 'filter': {'name':  name, 'hostid':  host_id  }})
            if len(host_webscenario_list) > 0:
                return host_webscenario_list[0]
            return None
        except Exception as e:
            self._module.fail_json(msg="Failed to get host webscenarios %s: %s" % (name, e))

    # create host webscenario
    def create_host_webscenario(self, host_id, name, agent, application_id, authentication, delay, http_password, http_proxy, http_user, retries,
                                    ssl_cert_file, ssl_key_file, ssl_key_password, status, verify_host, verify_peer, steps):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            parameters = {'hostid': host_id, 'name': name }
            if agent:
                parameters['agent'] = agent
            if application_id:
                parameters['applicationid'] = application_id
            if authentication:
                parameters['authentication'] = authentication
            if delay:
                parameters['delay'] = delay
            if http_password:
                parameters['http_password'] = http_password
            if http_proxy:
                parameters['http_proxy'] = http_proxy
            if http_user:
                parameters['http_user'] = http_user
            if retries:
                parameters['retries'] = retries
            if ssl_cert_file:
                parameters['ssl_cert_file'] = ssl_cert_file
            if ssl_key_file:
                parameters['ssl_key_file'] = ssl_key_file
            if ssl_key_password:
                parameters['ssl_key_password'] = ssl_key_password
            if status:
                parameters['status'] = status
            if verify_host:
                parameters['verify_host'] = verify_host
            if verify_peer:
                parameters['verify_peer'] = verify_peer
            if steps:
                parameters['steps'] = steps

            self._zapi.httptest.create(parameters)
            self._module.exit_json(changed=True, result="Successfully added webscenario %s" % name)
        except Exception as e:
            self._module.fail_json(msg="Failed to create webscenario %s: %s" % (name, e))

    # update host web scenario
    def update_host_webscenario(self, host_webscenario_obj, name, agent, application_id, authentication, delay, http_password, http_proxy, http_user, retries,
                                    ssl_cert_file, ssl_key_file, ssl_key_password, status, verify_host, verify_peer, steps):
        host_webscenario_id = host_webscenario_obj['httptestid']
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            parameters = { 'httptestid': host_webscenario_id, 'name': name }
            if agent:
                parameters['agent'] = agent
            if application_id:
                parameters['applicationid'] = application_id
            if authentication:
                parameters['authentication'] = authentication
            if delay:
                parameters['delay'] = delay
            if http_password:
                parameters['http_password'] = http_password
            if http_proxy:
                parameters['http_proxy'] = http_proxy
            if http_user:
                parameters['http_user'] = http_user
            if retries:
                parameters['retries'] = retries
            if ssl_cert_file:
                parameters['ssl_cert_file'] = ssl_cert_file
            if ssl_key_file:
                parameters['ssl_key_file'] = ssl_key_file
            if ssl_key_password:
                parameters['ssl_key_password'] = ssl_key_password
            if status:
                parameters['status'] = status
            if verify_host:
                parameters['verify_host'] = verify_host
            if verify_peer:
                parameters['verify_peer'] = verify_peer
            if steps:
                parameters['steps'] = steps

            self._zapi.httptest.update(parameters)
            self._module.exit_json(changed=True, result="Successfully updated host webscenario %s" % name)
        except Exception as e:
            self._module.fail_json(msg="Failed to update host webscenario %s: %s" % (name, e))

    # delete host webscenario
    def delete_host_webscenario(self, host_webscenario_obj, name):
        host_webscenario_id = host_webscenario_obj['httptestid']
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.httptest.delete([host_webscenario_id])
            self._module.exit_json(changed=True, result="Successfully deleted host webscenario %s" % name)
        except Exception as e:
            self._module.fail_json(msg="Failed to delete host webscenario %s: %s" % (name, e))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            server_url=dict(type='str', required=True, aliases=['url']),
            login_user=dict(type='str', required=True),
            login_password=dict(type='str', required=True, no_log=True),
            http_login_user=dict(type='str', required=False, default=None),
            http_login_password=dict(type='str', required=False, default=None, no_log=True),
            validate_certs=dict(type='bool', required=False, default=True),
            host_name=dict(type='str', required=True),
            name=dict(type='str', required=True),
            agent=dict(type='str', required=False, default=None),
            application_name=dict(type=str, required=False, default=None),
            authentication=dict(type=int, required=False, default=0),
            delay=dict(type=str, required=False, default=None),
            http_password=dict(type=str, required=False, default=None, no_log=True),
            http_proxy=dict(type=str, required=False, default=None),
            http_user=dict(type=str, required=False, default=None),
            retries=dict(type=int, required=False, default=1),
            ssl_cert_file=dict(type=str, required=False, default=None),
            ssl_key_file=dict(type=str, required=False, default=None),
            ssl_key_password=dict(type=str, required=False, default=None, no_log=True),
            status=dict(type=int, required=False, default=0),
            verify_host=dict(type=int, required=False, default=0),
            verify_peer=dict(type=int, required=False, default=0),
            steps=dict(type=list, required=False, default=[]),
            state=dict(default="present", choices=['present', 'absent']),
            timeout=dict(type='int', default=10),
            force=dict(type='bool', default=False)
        ),
        supports_check_mode=True
    )

    if not HAS_ZABBIX_API:
        module.fail_json(msg="Missing required zabbix-api module (check docs or install with: pip install zabbix-api)")
    server_url = module.params['server_url']
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    http_login_user = module.params['http_login_user']
    http_login_password = module.params['http_login_password']
    validate_certs = module.params['validate_certs']
    host_name = module.params['host_name']
    name = module.params['name']
    agent = module.params['agent']
    application_name = module.params['application_name']
    authentication = module.params['authentication']
    delay = module.params['delay']
    http_password = module.params['http_password']
    http_proxy = module.params['http_proxy']
    http_user = module.params['http_user']
    retries = module.params['retries']
    ssl_cert_file = module.params['ssl_cert_file']
    ssl_key_file = module.params['ssl_key_file']
    ssl_key_password = module.params['ssl_key_password']
    status = module.params['status']
    verify_host = module.params['verify_host']
    verify_peer = module.params['verify_peer']
    steps = module.params['steps']
    state = module.params['state']
    timeout = module.params['timeout']
    force = module.params['force']

    # convert enabled to 0; disabled to 1
    status = 1 if status == "disabled" else 0

    zbx = None
    # login to zabbix
    try:
        zbx = ZabbixAPIExtends(server_url, timeout=timeout, user=http_login_user, passwd=http_login_password,
                               validate_certs=validate_certs)
        zbx.login(login_user, login_password)
    except Exception as e:
        module.fail_json(msg="Failed to connect to Zabbix server: %s" % e)

    host_webscenario_class_obj = HostWebscenario(module, zbx)

    if host_name:
        host_id = host_webscenario_class_obj.get_host_id(host_name)
        host_webscenario_obj = host_webscenario_class_obj.get_host_webscenario(name, host_id)

    if application_name:
        application_id = host_webscenario_class_obj.get_application_id(application_name)
    else:
        application_id = None


    if state == 'absent':
        if not host_webscenario_obj:
            module.exit_json(changed=False, msg="Host Webscenario %s does not exist" % name)
        else:
            # delete a web scenario
            host_webscenario_class_obj.delete_host_webscenario(host_webscenario_obj, name)
    else:
        if not host_webscenario_obj:
            # create host web scenario
            host_webscenario_class_obj.create_host_webscenario(host_id, name, agent, application_id,
                                            authentication, delay, http_password, http_proxy,
                                            http_user, retries, ssl_cert_file, ssl_key_file, ssl_key_password,
                                            status, verify_host, verify_peer, steps)
        elif force:
            # update host web scenario
            host_webscenario_class_obj.update_host_webscenario(host_webscenario_obj, name, agent, application_id,
                                            authentication, delay, http_password, http_proxy,
                                            http_user, retries, ssl_cert_file, ssl_key_file, ssl_key_password,
                                            status, verify_host, verify_peer, steps)
        else:
            module.exit_json(changed=False, result="Host webscenario %s already exists and force is set to no" % name)


if __name__ == '__main__':
    main()
