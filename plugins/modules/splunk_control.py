#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Ansible module to control the Splunkd service using the REST API.
"""

from __future__ import absolute_import, division, print_function

import ssl
import sys
import time

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import urlencode, urlparse
from ansible.module_utils.six.moves.urllib.request import Request, urlopen


__metaclass__ = type


MODULE_NAME = "splunk_control"


DOCUMENTATION = '''
---
module: splunk_control
short_description: Control the Splunkd service
description:
    - Restart the Splunkd service using Ansible.
    - This module uses the Python Splunk SDK and requires access to the splunkd administrative port.
    - Authentication can be handled via either I(username) and I(password) or via I(token).
version_added: "0.10.0"
author: Lowell C. Alleman (@lowell80)
requirements:
    - splunk-sdk
options:
    splunkd_uri:
        description:
            - The Splunkd endpoint of the Splunk server to configure.
            - Defaults to the local server and default splunkd port.
        required: false
        default: https://localhost:8089
        aliases: [ uri ]

    username:
        description:
            - Splunk username for username/password authentication.
            - When provided, I(password) must also be specified.
        required: false
        default: null

    password:
        description:
            - The password for username/password authentication.
            - Must be provided if I(username) is provided.
        required: false
        default: null

    token:
        description:
            - Token to use when authentication has already taken place.
            - The C(token) can be specified instead of I(username) and I(password).
            - This module returns an output named I(token) that can be used for
              subsequent splunkd calls to the same splunkd endpoint.
        required: false
        default: null

    state:
        description:
            - Ensure the service is restarted or offlined.
        required: false
        default: running
        choices: [ running, restarted, offlined ]

    timeout:
        description:
            - Amount of time (in seconds) to wait for the server to come back online.
            - Set to 0 to disable the timeout and return immediately.
        required: false
        default: 300

    when_restart_required:
        description:
            - Only restart if the 'restart required' flag has been set.
            - By default, this module will force a restart.
        default: false
        choices: [true, false]

#notes:
'''

EXAMPLES = r'''
- name: Restart the local Splunkd service and wait for it to come back online
  cdillc.splunk.splunk_control:
    state: restarted
    username: admin
    password: manage
'''


try:
    import splunklib.client as client
    HAVE_SPLUNK_SDK = True
except ImportError:
    HAVE_SPLUNK_SDK = False


def connect(module, uri, username, password, token=None, owner=None, app=None, sharing=None):

    up = urlparse(uri)
    port = up.port or 8089
    if not token:
        service = client.connect(host=up.hostname, port=port, scheme=up.scheme,
                                 username=username, password=password,
                                 owner=owner, app=app, sharing=sharing)
    else:
        service = client.Service(host=up.hostname, port=port, scheme=up.scheme,
                                 token=token, owner=owner, app=app, sharing=sharing)
    if not service:
        module.fail_json(msg="Failure connecting to Splunkd:   "
                         "splunklib.client.connect() returned None.")
    return service


def server_restart(module, service, params):
    outputs = {}
    when_restart_required = params["when_restart_required"]
    timeout = params["timeout"]

    outputs["restart_required"] = service.restart_required
    if when_restart_required and not outputs["restart_required"]:
        outputs["changed"] = False
        return outputs

    if timeout:
        service.restart(timeout)
    else:
        service.restart()
    outputs["changed"] = True
    return outputs


# ##### Implementation without the Python Splunk SDK installed #################

urlopenkwargs = {}

if sys.version_info >= (3, 5):
    urlopenkwargs["context"] = ssl._create_unverified_context()
elif sys.version_info >= (2, 7, 9) and sys.version_info <= (3, 0, 0):

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    urlopenkwargs["context"] = ssl_context


def connect_nosdk(module, base_url, username, password, token=None):
    from xml.dom import minidom
    c = dict(base_url=base_url)
    if token:
        c["session_key"] = token
    else:
        authdata = urlencode({'username': username, 'password': password})
        request = Request(base_url + '/services/auth/login', data=authdata.encode("utf-8"))
        server_content = urlopen(request, **urlopenkwargs)
        session_key = minidom.parseString(server_content.read()).\
            getElementsByTagName('sessionKey')[0].childNodes[0].nodeValue
        c["session_key"] = session_key
    return c


def server_restart_nosdk(module, conn, params):
    outputs = {}
    base_url = conn["base_url"]
    session_key = conn["session_key"]
    timeout = params["timeout"]
    up = urlparse(base_url)
    port = up.port or 8089

    if not session_key.startswith("Splunk "):
        session_key = "Splunk " + session_key

    request = Request(base_url + '/services/server/control/restart',
                      method="POST",
                      data=None, headers=dict(Authorization=session_key))
    if timeout:
        # Wait for it to go down
        ping_it(up.hostname, port, timeout/2, "down")
        # Wait for it to come back online
        time.sleep(1)
        ping_it(up.hostname, port, timeout/2)

    results = urlopen(request, **urlopenkwargs)
    outputs["info"] = str(results.info())
    outputs["read"] = str(results.read())
    outputs["changed"] = True
    # To-do.  Implement some kind of ping waiting for the server to come back online.
    return outputs


def ping_it(host, port, timeout=300, wait_for="up"):
    import socket
    maxtime = time.time() + timeout
    s = None
    while time.time() < maxtime:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            # print("Connection opened!")
            if wait_for == "up":
                break
        except socket.error:
            if wait_for == "down":
                break
            # print("Can't connect yet...")
        finally:
            if s:
                s.close()
        time.sleep(1)

# ##### END Implementation without the Python Splunk SDK installed #############


def main():
    global HAVE_SPLUNK_SDK
    module = AnsibleModule(
        argument_spec=dict(
            # Splunkd endpoint and authentication
            splunkd_uri=dict(default="https://localhost:8089", aliases=["uri"]),
            username=dict(default=None),
            password=dict(default=None, no_log=True),
            token=dict(default=None, no_log=True),
            splunk_home=dict(default=None),
            # Settings for module behavior
            state=dict(default='running',
                       choices=['running', 'restarted', 'offlined']),
            timeout=dict(type='int', default=300),
            when_restart_required=dict(type='bool', default=False),
            # Hidden params
            no_sdk=dict(type='bool', default=False)
        )
    )

    p = module.params

    # Mostly for testing...
    if p["no_sdk"]:
        HAVE_SPLUNK_SDK = False

    if not ((p["username"] and p["password"]) or p["token"]):
        module.fail_json(msg="%s requires either (1) 'username' and 'password' parameters, "
                             "or (2) token parameter for Splunkd authentication" % (MODULE_NAME,))

    if HAVE_SPLUNK_SDK:
        try:
            service = connect(module, p['splunkd_uri'], p['username'], p['password'], p['token'])
        except Exception as e:
            module.fail_json(msg="Unable to connect to splunkd.  Exception: %s" % e)
    else:
        service = connect_nosdk(module, p['splunkd_uri'], p['username'], p['password'], p['token'])

    if p["state"] == "restarted":
        if HAVE_SPLUNK_SDK:
            output = server_restart(module, service, module.params)
        else:
            output = server_restart_nosdk(module, service, module.params)
    elif p["state"] == "offlined":
        raise NotImplementedError
    elif p["state"] == "running":
        raise NotImplementedError
    else:
        module.fail_json(msg="Unsupported state of '%s'" % p["state"])

    # For convenience, pass along some of the input parameters
    output["params"] = p
    output["have_sdk"] = HAVE_SPLUNK_SDK
    module.exit_json(**output)


if __name__ == '__main__':
    main()
