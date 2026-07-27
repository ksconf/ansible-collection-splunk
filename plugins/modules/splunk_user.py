#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Ansible module to manage Splunk users via the Splunkd REST API.
"""

from __future__ import absolute_import, division, print_function

import os
import ssl
import sys

from ansible.module_utils.basic import AnsibleModule


__metaclass__ = type


MODULE_NAME = "splunk_user"


# Search path for Splunk SDK, which is bundled as part of some Splunk apps
# This is only used if the splunklib import fails
SPLUNK_SDK_SEARCH_PATH = [
    "lib/python37/site-packages",
    "etc/apps/splunk_management_console/bin",
]


DOCUMENTATION = r'''
---
module: splunk_user
short_description: Manage Splunk user accounts
description:
    - Create, delete, and update local Splunk user accounts with Ansible.
    - This module uses the Python Splunk SDK and requires access to the splunkd administrative port.
    - Authentication can be handled via either I(username) and I(password) or via I(token).
version_added: "0.9.0"
author: Lowell C. Alleman <lowell.alleman@cdillc.com>
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
            - Splunk username for username/password authentication to Splunkd.
            - When provided, I(password) must also be specified.
        required: false
        default: null

    password:
        description:
            - The password for username/password authentication to Splunkd.
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

    splunk_home:
        description:
            - Path to Splunk installation.
            - This is used if the splunk-sdk is not installed for all users.
        required: false
        default: null

    state:
        description:
            - Ensure the user is either present or absent; or list the contents of the user's configuration.
            - With C(present), existing users are updated in place.
              See notes regarding specific handling of the I(roles), I(splunk_pass), and I(force_change_pass).
        required: false
        default: present
        choices: [present, absent, list]

    update_password:
        description:
            - Replace the existing password with the one specified in I(password).
            - When I(true) this module will always report changed since there is no way to
              determine if the new password is different than the currently assigned password.
        required: false
        default: false
        type: bool

    append_roles:
        description:
            - When true, the specified I(roles) will be appended to the user's existing roles.
        required: false
        default: false
        type: bool

    splunk_user:
        description:
            - Name of the user to create, modify or delete.
        required: true
        default: null
        aliases: [ name ]

    splunk_pass:
        description:
            - Password for the Splunk user account being created or modified.
            - See the notes regarding changing passwords under the I(update_password) option.
            - This option is required when C(state=present).
        required: false
        default: null

    roles:
        description:
            - List of roles associated with the Splunk user.
            - By default this will override any users existing role membership.
              Use I(append_roles=true) to change this behavior to be additive.
        type: list
        elements: str
        required: true
        default: ["user"]

    tz:
        description:
            - Timezone associated with the Splunk user.
        required: false
        default: null
        aliases: [ timezone ]

    realname:
        description:
            - The full name (comment) of the user account.
        required: false
        default: null
        aliases: [ fullname, comment ]

    defaultapp:
        description:
            - The default Splunk application the user sees when they login to Splunk Web.
        required: false
        default: null
        aliases: [ defaultApp ]

    email:
        description:
            - Email address associated with the Splunk user.
        required: false
        default: null

    force_change_pass:
        description:
            - Force user to change password.
              This field is set when the user is first created or when I(update_password=true).
        required: false
        default: null
        type: bool

    update_force_change_pass:
        description:
            - Use in combination with I(force_change_pass) to force an update to an existing user.
            - Whenever this is set to I(true) the module will always report as changed.
              The Splunk REST api does not allow the C(force-change-pass) to be read.
        required: false
        default: false
        type: bool

notes:
    - The default behavior of this module will only set I(password) and I(force_change_pass) when
      the user is first created.
      This enables mostly idempotent behavior for other parameters without unwanted side effects.
      Set I(update_password=true) to explicitly update the password of an existing account,
      or I(update_force_change_pass=true) to force a user to change their current password.
      Similarly, updates to the I(roles) field can be set to overwrite roles by default or append
      new roles when I(append_roles=true).
'''

RETURN = r'''
result:
  description:
    - The overall result of the module run.
    - Options include C(created), C(updated), C(deleted), or C(unchanged).
  returned: always
  type: str
  sample: updated
token:
  description:
    - The Splunk auth token created used for the REST API calls.
    - This value can be passed into I(token) of a subsequent REST-based operation.
  type: str
  returned: always
updated_attrs:
  description: A list of attributes that were set.
  type: list
content:
  description: User attributes as returned by Splunk.
               A few highlights have provided below for quick reference.
  type: dict
  returned: >-
    when user is listed, created, or updated.  Upon deletion this is shown too,
    but subsequent invocations of I(state=absent) will return an empty dictionary.
  contains:
    capabilities:
      description: A list of effectively Splunk capabilities for the user
      type: list
      elements: str
      sample: [search, install_apps, ...]
    defaultApp:
      type: str
    email:
      type: str
    relname:
      description: Real user name
      type: str
    restart_background_jobs:
      type: str
    roles:
      description: Splunk roles assigned to user.
      sample: [user, power]
    search_assistant:
      type: str
      sample: compact
    search_auto_format:
      type: str
      sample: "0"
    search_line_numbers:
      type: str
      sample: "0"
    search_syntax_highlighting:
      type: str
      sample: light
    search_use_advanced_editor:
      type: str
      sample: "1"
    theme:
      type: str
      sample: enterprise
    locked-out:
      type: str
      sample: "0"
    tz:
      type: str
      description: Time zone
endpoint:
  description: URL used to edit the user object
  type: str
  returned: always
'''

EXAMPLES = r'''
- name: Create a new user named 'bob'
  cdillc.splunk.splunk_user:
    state: present
    username: admin
    password: "{{ splunk_admin_password }}"
    splunk_user: bob
    splunk_pass: aReallyGoodPassword
    roles: user,admin
    tz: America/New_York

# Run splunk_user on the controller if missing splunksdk on targets
- name: Create a new user remotely
  cdillc.splunk.splunk_user:
    state: present
    splunkd_uri: "https://{{ ansible_fqdn }}:{{ splunkd_port }}"
    username: "{{ splunk_admin_username }}"
    password: "{{ splunk_admin_password }}"
    splunk_user: bob
    splunk_pass: aReallyGoodPassword
    roles:
      - user
      - admin
  delegate_to: localhost

- name: Add bob to the 'delete_stuff' role.  (existing roles are preserved)
  cdillc.splunk.splunk_user:
    username: admin
    password: "{{ splunk_admin_password }}"
    splunk_user: bob
    roles: delete_stuff
    append_roles: true

- name: Terminate bob after data deletion incident
  cdillc.splunk.splunk_user:
    state: absent
    username: admin
    password: "{{ splunk_admin_password }}"
    splunk_user: bob

- name: Change the password of existing user 'joe'
  cdillc.splunk.splunk_user:
    username: admin
    password: "{{ splunk_admin_password }}"
    splunk_user: joe
    splunk_pass: NewPassWord
    update_password: true

- name: Force existing user 'joe' to change their password at next login
  cdillc.splunk.splunk_user:
    splunkd_uri: https://splunk-sh01.megacorp.example:8089
    username: admin
    password: "{{ splunk_admin_password }}"
    splunk_user: joe
    force_change_pass: true
    update_force_change_pass: true

- name: Retrieve information about top users
  cdillc.splunk.splunk_user:
    state: list
    username: admin
    password: "{{ splunk_admin_password }}"
    splunk_user: "{{ item }}"
  register: user_info
  loop:
    - bob
    - joe
    - henry
'''


def import_splunk_sdk(splunk_home=None, search_paths=None):
    sys_path_reset = None
    if splunk_home:
        # Take a backup copy
        sys_path_reset = list(sys.path)
        for p in search_paths:
            sys.path.append(os.path.join(splunk_home, p))
    try:
        import splunklib.client as client

        # Assume that we only need to do this with Splunk SDK living under the SPLUNK_HOME;
        # OS-level install should be up-to-date via other mechanisms.
        evil_ssl_nocertcheck_hack()
    except ImportError:
        client = None
    if sys_path_reset:
        del sys.path[:]
        sys.path.extend(sys_path_reset)
    return client


__default__create_default_https_context = None


def evil_ssl_nocertcheck_hack():
    """
    For newer versions of Python (2.7.9) and older version of the splunk-sdk,
    this hack lets us revert to the old behavior and keep thing moving.
    """
    global __default__create_default_https_context
    import splunklib
    if splunklib.__version__ <= "1.3.1" and sys.version_info >= (2, 7, 9):
        __default__create_default_https_context = ssl._create_default_https_context
        ssl._create_default_https_context = ssl._create_unverified_context


def connect(module, uri, username, password, token=None, owner=None, app=None, sharing=None):
    from ansible.module_utils.six.moves.urllib.parse import urlparse
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
        module.fail_json(msg="Failure connecting to Splunkd:  "
                         "splunklib.client.connect() returned None.")
    return service


def create_user(module, service, params):
    """
    Create or or update Splunk local user.
    """
    splunk_user = params["splunk_user"]
    splunk_pass = params["splunk_pass"]
    roles = params["roles"]
    realname = params["realname"]
    tz = params["tz"]
    email = params["email"]
    defaultapp = params["defaultapp"]
    update_password = params["update_password"]
    append_roles = params["append_roles"]
    force_change_pass = params["force_change_pass"]
    update_force_change_pass = params["update_force_change_pass"]

    output = {}
    changes = {}
    atrsupd = []
    updating_user = True    # Updating an existing user account

    try:
        user = service.users[splunk_user]
    except KeyError:
        user = service.users.create(username=splunk_user, password=splunk_pass,
                                    roles=roles,
                                    **{"force-change-pass": bool(force_change_pass)})
        atrsupd.extend(["user", "password", "roles"])
        if force_change_pass:
            atrsupd.append("force_change_pass")
        updating_user = False

    creating_user = not updating_user  # Redundant, but makes logic easier to follow

    # Update password for existing user, but only in 'update_password' mode, and if the password was provided
    if updating_user and update_password and splunk_pass:
        changes["password"] = splunk_pass
        atrsupd.append("password")

    if force_change_pass is not None and updating_user and update_force_change_pass:
        changes["force-change-pass"] = force_change_pass
        atrsupd.append("force_change_pass")

    # Look at individual parameter values and update as necessary
    if roles and set(roles) != set(user.roles):
        new_roles = set(roles)
        if append_roles:
            new_roles.update(user.roles)
        changes['roles'] = list(new_roles)
        atrsupd.append("roles")

    if realname and realname != user.realname:
        changes['realname'] = realname
        atrsupd.append("realname")

    if tz and tz != user.tz:
        changes['tz'] = tz
        atrsupd.append("tz")

    if email and email != user.email:
        changes['email'] = email
        atrsupd.append("email")

    if defaultapp and defaultapp != user.defaultApp:
        changes['defaultApp'] = defaultapp
        atrsupd.append("defaultApp")

    output["result"] = "unchanged"
    if creating_user:
        output["changed"] = True
        output["result"] = "created"

    if changes:
        user.update(**changes).refresh()
        output["changed"] = True
        if updating_user:
            output["result"] = "updated"

    output["updated_attrs"] = atrsupd
    output["content"] = dict(user.content)
    output["endpoint"] = str(user.links['edit'])
    return output


def delete_user(module, service, params):
    splunk_user = params["splunk_user"]
    output = {}
    try:
        user = service.users[splunk_user]
        # May be informative to the caller (possibly a "move" use-case)
        output["content"] = dict(user.content)
        output["result"] = "deleted"
        try:
            user.delete()
        except Exception as e:
            output["failed"] = True
            output["msg"] = "Unable to delete user '%s'  Exception:  %s" % (splunk_user, e)
            return output
        output["changed"] = True
    except KeyError:
        output["result"] = "missing"
        output["changed"] = False
        # Empty content - For output consistency
        output["content"] = {}
    return output


def list_user(module, service, params):
    """
    Return an existing user record
    """
    splunk_user = params["splunk_user"]
    output = {}
    try:
        user = service.users[splunk_user]
        output["result"] = "present"
    except KeyError:
        output["result"] = "missing"
        output["msg"] = "Unable to find user '%s'" % (splunk_user)
        output["failed"] = True
        return output
    output["content"] = dict(user.content)
    output["endpoint"] = str(user.links['list'])
    return output


def main():
    global client

    module = AnsibleModule(
        argument_spec=dict(
            # Splunkd endpoint and authentication
            splunkd_uri=dict(default="https://localhost:8089", aliases=["uri"]),
            username=dict(default=None),
            password=dict(default=None, no_log=True),
            token=dict(default=None, no_log=True),
            splunk_home=dict(default=None),
            # Settings for module behavior
            state=dict(default='present',
                       choices=['present', 'absent', 'list']),
            update_password=dict(type='bool', default=False, no_log=False),
            update_force_change_pass=dict(type='bool', default=False, no_log=False),
            append_roles=dict(type='bool', default=False),
            # User settings
            splunk_user=dict(required=True),
            splunk_pass=dict(default=None, type="str", no_log=True),
            roles=dict(type="list", elements="str", default=["user"]),
            tz=dict(default=None),
            realname=dict(default=None),
            defaultapp=dict(default=None),
            email=dict(default=None),
            force_change_pass=dict(default=None, type="bool", no_log=False)
        ),
    )

    p = module.params

    if client is None:
        # Try to find the splunk-sdk bundled under $SPLUNK_HOME if it's not globally available
        if p["splunk_home"]:
            client = import_splunk_sdk(p["splunk_home"], SPLUNK_SDK_SEARCH_PATH)

    if client is None:
        module.fail_json(msg='splunk-sdk required for this module')

    from splunklib.binding import HTTPError

    if not ((p["username"] and p["password"]) or p["token"]):
        module.fail_json(msg="%s requires either (1) 'username' and 'password' parameters, "
                             "or (2) token parameter for Splunkd authentication" % (MODULE_NAME,))

    if p["state"] == "present" and p["update_password"] and not p["splunk_pass"] and p["force_change_pass"] is None:
        module.fail_json(msg=f"{MODULE_NAME} requires setting either (1) 'splunk_pass' or "
                         "(2) 'force_change_pass' when in 'update_password' mode.")

    try:
        service = connect(module, p['splunkd_uri'], p['username'],
                          p['password'], p['token'], sharing="system")
    except Exception as e:
        module.fail_json(msg="Unable to connect to splunkd.  Exception: %s" % e)

    if p["state"] in ("present", "absent") and p["username"] == p["splunk_user"]:
        module.fail_json(
            msg=f"{MODULE_NAME} does not support updating or removing the login user {p['username']}.")
        # It technically is possible to update ones own password, but we'd need capture/pass "oldpassword".
        # Frankly, this doesn't seem very important.  But send a FR/PR if I'm wrong.

    try:
        if p["state"] == "present":
            output = create_user(module, service, module.params)
        elif p["state"] == "absent":
            output = delete_user(module, service, module.params)
        elif p["state"] == "list":
            output = list_user(module, service, module.params)
        else:
            module.fail_json(msg="Unsupported state of '%s'" % p["state"])
    except HTTPError as e:
        module.fail_json(msg=f"Error returned from splunkd: {e}", rc=5)

    # For convenience, pass along some of the input parameters
    # Add auth 'token' which can be used for subsequent calls in the same play.
    output["token"] = service.token
    # DEBUG, or is this worth keeping?
    output["params"] = p
    output["_splunksdk_path"] = client.__file__
    module.exit_json(**output)


if __name__ == '__main__':
    client = import_splunk_sdk()
    main()


# Reset ugliness of SSL hack (this could matter when Ansible is running in pipelining mode)
if __default__create_default_https_context:
    ssl._create_default_https_context = __default__create_default_https_context
