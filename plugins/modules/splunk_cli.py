#!/usr/bin/python
# -*- coding: utf-8 -*-
# Heavy inspiration from https://github.com/ansible/ansible/blob/devel/lib/ansible/modules/command.py

"""
Ansible module to run the Splunk command line interface


Session key / token support:
    File:  $SPLUNK_HOME/.splunk/authToken_{{inventory_hostname}}_{{splunkd_port}}
    Content:
        <auth>
            <username>{{username}}</username>
            <sessionkey>{{ token | replace("Splunk ","") }}</sessionkey>
            <cookie>splunkd_{{splunkd_port}}</cookie>
        </auth>
"""

from __future__ import absolute_import, division, print_function

import datetime
import os
import re
import shlex

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule


__metaclass__ = type


MODULE_NAME = "splunk_cli"


DOCUMENTATION = '''
---
module: splunk_cli
short_description: Splunk command line interface
description:
    - This is a lightweight wrapper around the Splunk CLI that handles auth
      parameter hiding and some other niceties.
    - This is a drop-in replacement for M(ansible.builtin.command).
      When converting, simply replace authenticated calls using C(-auth user:password) to
      use I(username) and (password) module options.
      Additional sensitive arguments can be protected too using I(hidden_args).
    - Calls to remote splunkd instance can be handled by specifying I(splunkd_uri).
version_added: "0.9.0"
author: Lowell C. Alleman (@lowell80)

extends_documentation_fragment:
    - action_common_attributes
    - action_common_attributes.raw

attributes:
    check_mode:
        details: while the command itself is arbitrary and cannot be subject to
                 the check mode semantics it adds C(creates)/C(removes) options
                 as a workaround
        support: partial
    diff_mode:
        support: none
    platform:
      support: full
      platforms: posix
    raw:
      support: none

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

#    token:
#        description:
#            - Token to use when authentication has already taken place.
#            - The C(token) can be specified instead of I(username) and I(password).
#            - This module returns an output named I(token) that can be used for
#              subsequent splunkd calls to the same splunkd endpoint.
#        required: false
#        default: null

    hidden_args:
        description:
            - Specify additional arguments without logging values.
            - These will be appended to C(cmd) when the command is called.
            - A leading dash will be added to keys to simplify the YAML syntax.
        required: false
        default: null
        type: dict

    splunk_home:
        description:
            - The Splunk installation home.  $SPLUNK_HOME
            - This value is required unless the first argument to I(cmd) is the absolute path
              to the splunk executable (often C(/opt/splunk/bin/splunk))
        required: false
        default: /opt/splunk

    cmd:
        description:
            - Command line arguments to the Splunk CLI
            - The initial C(splunk) command is optional as long as C(splunk_home) is provided.
        required: true
        default: null

notes:
    - As of v0.20.0 it's now possible to pass in the full path to splunk in I(cmd) and thus
      avoid providing I(splunk_home).
      This allows for a closer match-up with the the builtin command module.
'''

EXAMPLES = r'''
- name: Reload the deployment server
  cdillc.splunk.splunk_cli:
    cmd: "{{splunk_home}}/bin/splunk reload deploy-server"
    username: "{{splunk_admin_user}}"
    password: "{{splunk_admin_pass}}"

- name: Update CM URL and secret (note that '-secret' is not logged)
  cdillc.splunk.splunk_cli:
    cmd: edit cluster-config -master_uri {{cm_url}}
    hidden_args:
      secret: "{{ cm_secret }}"
    splunk_home: "{{splunk_home}}"
    username: "{{splunk_admin_user}}"
    password: "{{splunk_admin_pass}}"

# Replacement for adding a search peer
#   command: splunk add search-server -auth {{splunk_admin_user}}:{{splunk_admin_pass}}
#            {{sh_url}} -remoteUsername {{sh_user}} -remotePassword {{sh_pass}}
# This version protect the local and remote credentials
- name: Add search peer
  cdillc.splunk.splunk_cli:
    cmd: add search-server {{sh_url}}
    hidden_args:
      remoteUsername: "{{ sh_user }}"
      remotePassword: "{{ sh_pass }}"
    splunk_home: "{{splunk_home}}"
    username: "{{splunk_admin_user}}"
    password: "{{splunk_admin_pass}}"
    creates: "{{splunk_home}}/.search-peer-added-{{ sh_url | urlencode }}"
    create_on_success: true
'''


def main():
    # Note attempting to use '_raw_params' here, like `command`` does, doesn't
    # work.  Apparently you must be on the the "special list" (RAW_PARAM_MODULES)
    # this must be something that Ansible wants to restrict.
    # Therefore cmd="..." syntax must be use.
    module = AnsibleModule(
        argument_spec=dict(
            cmd=dict(type="str", required=True),
            splunk_home=dict(required=False, type="str"),
            splunkd_uri=dict(default=None, type="str", aliases=["uri", "splunk_uri"]),
            username=dict(default=None, type="str"),
            password=dict(default=None, type="str", no_log=True),
            # token=dict(default=None, no_log=True),
            hidden_args=dict(type="dict", default=None, no_log=True),
            # Borrowed from the shell/command module
            creates=dict(default=None, type="str"),
            removes=dict(default=None, type="str"),
            create_on_success=dict(type="bool", default=None),
        )
    )
    cmd = module.params["cmd"]
    splunk_home = module.params["splunk_home"]
    splunkd_uri = module.params['splunkd_uri']
    splunk_user = module.params['username']
    splunk_pass = module.params['password']
    creates = module.params['creates']
    removes = module.params['removes']
    hidden_args = module.params["hidden_args"]
    create_on_success = module.params['create_on_success']

    if (splunk_user or splunk_pass) and not (splunk_user and splunk_pass):
        module.fail_json(msg="Both 'username' and 'password' must be specified at the same time.")

    if cmd.strip() == '':
        module.fail_json(rc=256, msg="no command given")

    try:
        args = shlex.split(cmd)
    except ValueError as e:
        module.fail_json(msg=f"Failed to parse command into arguments.  {e}  "
                         f"cmd={cmd!r}")

    if "-auth" in args:
        # In a later version this should be an error
        module.warn("Found '-auth' in cmd.  Please use the 'username' and 'password' module "
                    "arguments instead.  In the future this will trigger a failure.")

    if splunk_home:
        splunk_home = os.path.abspath(os.path.expanduser(splunk_home))

    match = re.match(r'(.+)/bin/splunkd?$', args[0])
    if match:
        splunk_home2 = os.path.abspath(os.path.expanduser(match.group(1)))
        if splunk_home and splunk_home != splunk_home2:
            module.warning(f"Splunk home disagreement:  splunk_home shows '{splunk_home}', "
                           f"but cmd indicates '{splunk_home2}'.  Using the later.")
        splunk_home = splunk_home2
        executable = args[0]
    elif not splunk_home:
        module.fail_json(msg="No known value for splunk_home!  Must provide 'splunk_home' "
                         "or full path to splunk executable via 'cmd'")
    else:
        # Make sure that 'splunk' is the first argument
        args.insert(0, os.path.join(splunk_home, "bin", "splunk"))
        executable = os.path.join(splunk_home, "bin", "splunk")

    # Q: Why chdir to splunk home, should the caller have control of this?
    try:
        os.chdir(splunk_home)
    except (IOError, OSError) as e:
        module.fail_json(rc=257, msg='Unable to change directory before execution: %s' % to_text(e))

    if creates:
        # do not run the command if the line contains creates=filename
        # and the filename already exists.
        v = os.path.expanduser(creates)
        if os.path.exists(v):
            module.exit_json(
                cmd=args, changed=False, rc=0,
                stdout="skipped, since %s exists" % v,
                stderr=False
            )

    if removes:
        # do not run the command if the line contains removes=filename
        # and the filename does not exist.  This allows idempotence
        # of command executions.
        v = os.path.expanduser(removes)
        if not os.path.exists(v):
            module.exit_json(
                cmd=args, changed=False, rc=0,
                stdout="skipped, since %s does not exist" % v,
                stderr=False
            )

    if splunk_user:
        args.append("-auth")
        args.append("%s:%s" % (splunk_user, splunk_pass))

    if splunkd_uri:
        # Tell splunk CLI to issue command to remote Splunk instance
        args.append("-uri")
        args.append(splunkd_uri)

    if hidden_args:
        for arg, value in hidden_args.items():
            if not arg.startswith("-"):
                arg = "-" + arg
            args.append(arg)
            args.append(to_text(value))

    start_time = datetime.datetime.now()

    rc, out, err = module.run_command(args, executable=executable, use_unsafe_shell=False)

    end_time = datetime.datetime.now()
    delta = end_time - start_time

    if out is None:
        out = ''
    if err is None:
        err = ''

    if rc == 0 and create_on_success:
        open(os.path.expanduser(create_on_success), "w").write("MARKER FILE CREATED")
    module.exit_json(
        cmd=args,
        stdout=to_text(out).rstrip("\r\n"),
        stderr=to_text(err).rstrip("\r\n"),
        rc=rc,
        start=to_text(start_time),
        end=to_text(end_time),
        delta=to_text(delta),
        changed=True,
    )


if __name__ == '__main__':
    main()
