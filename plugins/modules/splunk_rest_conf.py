#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Ansible module to manage Splunk props via the Splunkd REST API.


To-do:
    - Improve error handling.  Not sure what all stuff can throw exceptions.
    - Add support for tracking which keys were updated.  See note below on complexities.
    - Handle round-trip issues.  See notes below.
    - Implement the 'del_unknown' option.

===== Round-trip issues =====
It's possible that updates to "special" fields like "eai:*" and maybe even
"disabled" will cause issues. Right now all keys are returned when
"state=list" which means that a round-trip from one call to another could
break things.

Possible solutions could include (1) stripping out
these values from the output, (2) moving these values to a separate output or
"metadata" sub dictionary, or (3) apply some kind of filtering to the inbound
'settings' dictionary.  It's also possible that this is all natively handled
by the Splunk Python SDK.  Not sure.  This all needs tested.


===== Tracking changes =====
Q:  Do we want to track which keys were updated?  Seems like it could be
helpful but a solid use case hasn't emerged.  It's more complicated that first
thought.  Is a change
    (1) a full listing of all keys in settings,
    (2) the difference between server content and given 'settings', or
    (3) keys that were actually updated on the server?
We don't know if some keys may be rejected when pushed to the server.  Also,
booleans have multiple identical values which could trigger false positives.
Seems like we should wait until we actually need this functionality before
adding it.
"""

from __future__ import absolute_import, division, print_function

from ansible.module_utils.basic import AnsibleModule


__metaclass__ = type


MODULE_NAME = "splunk_rest_conf"


DOCUMENTATION = '''
---
module: splunk_rest_conf
short_description: Manage adhoc configurations via the Splunk REST API
description:
    - Manage the content of Splunk C(.conf) files via Ansible.
    - This module uses the Python Splunk SDK to fetch and modify configuration settings
      via the Splunk REST endpoint of a running C(splunkd) service.
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
            - Ensure the configuration settings are either present or absent, or to list existing settings.
            - The C(content) output contains the final setting.
            - If the state is absent, the C(content) output will be missing if the stanza was previously removed.
        required: false
        default: present
        choices: [present, absent, list]

    conf:
        description:
            - The configuration type to manage or view.
            - The list of choices provided here are for reference only and are not enforced by the module.
            - Any value supported by the underling Splunk SDK / REST API should work.
        required: true
        default: null
        choices: [ server, props, transforms, macros ]

    stanza:
        description:
            - The stanza to edit within the given I(conf) configuration file.
        required: true
        default: null

    del_unknown:
        description:
            - Not implemented yet!
            - Remove any keys in the servers configuration that are not present within the I(settings) dictionary.
            - This feature does not yet exist in the code.
            - Currently only adding or updated keys or removing the entire stanza is supported.
        required: false
        default: false
        type: bool

    restart_on_change:
        description:
            - Enable an immediate splunkd restart on configuration change.
        required: false
        default: false
        type: bool

    restart_timeout:
        description:
            - Amount of time to wait for the restart to complete.
            - If I(restart_timeout) is 0 then the restart wait is disabled.
        required: false
        default: null


    settings:
        description:
            - The dictionary of key/values to push into the given stanza.
            - The I(settings) option must be provided when C(state=present).
            - The final value of the stanza is returned via the I(content) output.
        required: false
        default: {}

    defaults:
        description:
            - The dictionary of key/values to push into a newly created stanza.
            - Use this to set stanza defaults that you do not want to override on subsequent runs.
            - The I(defaults) option is only used when C(state=present) and a new stanza is created.
            - If a new stanza is created, the I(result) output will contain the value C(created).
        required: false
        default: {}

    owner:
        description:
            - The Splunk owner (namespace) of the stanza.
            - Use the special value of C(nobody) if no owner is desired.
            - The value of C(sharing) may also impact the owner.
        required: false
        default: null

    app:
        description:
            - The Splunk "app" (namespace) where the stanza lives or will be created.
            - The special value of C(system) can be used to indicate no app association.
        required: false
        default: null

    sharing:
        description:
            - The Splunk sharing mode to use for stanza creation or modification.
            - See the note on "Splunk namespaces" below.
            - The default C(global) will create entries that are placed in C(etc/system/local/)
        required: false
        default: global
        choices: [ user, app, global, system ]
notes:
    - The I(owner), I(app), and I(sharing) options determine the Splunk namespace.
      See U(http://dev.splunk.com/python#namespaces) for more details.

    - Not all changes take effect immediately.
      Even though changes are persisted to the config quickly, like editing C(.conf) file by hand,
      a splunkd restart or endpoint reload may be necessary for some changes to take effect.
      (The exact behavior is unknown.)

'''


EXAMPLES = r'''
- name: Change the minimum free disk space
  cdillc.splunk.splunk_rest_conf:
    state: present
    username: admin
    password: "{{ secret_password }}"
    conf: server
    stanza: diskUsage
    settings:
      minFreeSpace: 3000

# For comparison, here's the same (offline) change using ini_file:
- name: Change the minimum free disk space offline
  community.general.ini_file:
    dest: "{{ splunk_home }}/etc/system/local/server.conf"
    section: diskUsage
    option: minFreeSpace
    value: 3000

# Update a Splunk license pool. description and quota are only set the first
# time the pool is created; afterwards Ansible only updates the "slaves" key.
- name: Update Splunk license pool slaves
  cdillc.splunk.splunk_rest_conf:
    splunkd_uri: "{{ splunk_license_master_uri }}"
    username: "{{ splunk_admin_user }}"
    password: "{{ splunk_admin_pass }}"
    state: present
    conf: server
    stanza: "lmpool:MyLicesePool"
    settings:
      slaves: "{{ guids }}"
      stack_id: enterprise
    defaults:
      description: NOTICE - The list of slaves is automatically updated by Ansible
      quota: 1073741824
'''


try:
    import splunklib.client as client
    HAVE_SPLUNK_SDK = True
except ImportError:
    HAVE_SPLUNK_SDK = False


class SplunkRestConf(object):
    def __init__(self, module):
        self.module = module

    def connectUri(self, uri, username, password, token=None, owner=None, app=None, sharing=None):
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
            self.module.fail_json(msg="Failure connecting to Splunkd:  "
                                  "splunklib.client.connect() returned None.")
        self.service = service

    def getToken(self):
        return self.service.token

    '''
    def filterDictKeys(self, d):
        """
        Remove Splunk internal 'eai:*' keys from a dictionary to allow round
        trips between "list" and "present" (update) calls.
        """
    '''

    def contentEquals(self, baseline, update):
        """
        Compare to 'content' dictionaries.  No need to do a full comparison,
        we only need to know if there's anything different in update.  Keys
        that are unique to baseline don't matter since they will not be
        updated.

        TODO:  Add support for boolean comparison.  The "disabled" key is
        easy, the others will be more complicated.  (Of course the simplest
        solution is to teach the users to use the canonical names for boolean
        values.)
        """
        for (key, value) in update.items():
            if key not in baseline:
                return False
            if str(baseline[key]) != str(value):
                return False
        return True

    def applySettings(self, confName, stanzaName, settings, defaults=None, del_unknown=False):
        """
        Create or update a record
        """
        output = {}
        if del_unknown:
            output["failed"] = True
            output["msg"] = "The 'del_unknown' functionality hasn't been implemented yet!"
            return output
        stanza_dict = {}
        created = False
        do_update = False

        # This can happen due to a bad conf type OR an invalid (or disabled) app namespace
        try:
            conf = self.service.confs[confName]
        except KeyError as e:
            output["failed"] = True
            output["msg"] = "Conf error: {0}".format(e)
            return output

        # Attempt to fetch existing entry, or create a new one
        try:
            stanza = conf[stanzaName]
        except KeyError:
            stanza = conf.create(stanzaName)
            created = True

        # Determine if settings need to be updated
        if created:
            output["result"] = "created"
            # Only apply defaults when creating a new stanza
            if defaults:
                stanza_dict.update(defaults)
            stanza_dict.update(settings)
            init_content = {}
        else:
            output["result"] = "updated"
            stanza_dict = settings
            init_content = dict(stanza.content)
            if not self.contentEquals(init_content, stanza_dict):
                do_update = True

        if created or do_update:
            # Update local entity (I think)
            stanza.submit(stanza_dict)
            # Send updates to splunkd
            stanza.update()
            # Refresh my local copy based on what the server accepted
            stanza.refresh()

        # output["stanza_dict"] = stanza_dict          #DEBUGGING
        output["content"] = dict(stanza.content)
        # output["content_initital"] = init_content     # For debugging
        # Or is it better to do a before/after comparison?
        output["changed"] = created or do_update
        # output["changed_dictdiff"] = init_content != output["content"]      # DEBUGGING
        output["endpoint"] = str(stanza.links['edit'])
        return output

    def listSettings(self, confName, stanzaName):
        """
        Return an existing configuration record
        """
        output = {}
        try:
            conf = self.service.confs[confName]
        except KeyError as e:
            output["failed"] = True
            output["msg"] = "Conf error: {0}".format(e)
            return output
        try:
            stanza = conf[stanzaName]
            output["result"] = "present"
        except KeyError:
            output["result"] = "missing"
            output["msg"] = "Unable to find [%s] in %s.conf" % (stanzaName, confName)
            output["failed"] = True
            return output
        output["content"] = dict(stanza.content)
        output["endpoint"] = str(stanza.links['list'])
        return output

    def deleteSettings(self, confName, stanzaName):
        """
        Remove an existing configuration record, if it exists.
        """
        output = {}
        try:
            conf = self.service.confs[confName]
        except KeyError as e:
            output["failed"] = True
            output["msg"] = "Conf error: {0}".format(e)
            return output
        try:
            stanza = conf[stanzaName]
            # May be informative to the caller (possibly a "move" use-case)
            output["content"] = dict(stanza.content)
            output["result"] = "deleted"
            try:
                stanza.delete()
            except Exception as e:
                output["failed"] = True
                output["msg"] = "Unable to delete [%s] in %s.conf.  "\
                                " Exception:  %s" % (stanzaName, confName, e)
                return output
            output["changed"] = True
        except KeyError:
            output["result"] = "missing"
            output["changed"] = False
            # Empty content - For output consistency
            output["content"] = {}
        return output


def main():
    module = AnsibleModule(
        argument_spec=dict(
            # Splunkd endpoint and authentication
            splunkd_uri=dict(default="https://localhost:8089", aliases=["uri"]),
            username=dict(default=None),
            password=dict(default=None, no_log=True),
            token=dict(default=None, no_log=True),
            # Conf settings change
            state=dict(default='present',
                       choices=['present', 'absent', 'list']),
            conf=dict(required=True),
            stanza=dict(required=True),
            del_unknown=dict(type='bool', default=False),
            restart_on_change=dict(type='bool', default=False),
            restart_timeout=dict(type='int', default=None),
            # settings are required when state=present.
            settings=dict(type='dict', default={}),
            defaults=dict(type='dict', default={}),
            # Splunk namespace options
            owner=dict(default=None),
            app=dict(default=None),
            sharing=dict(default="global",
                         choices=["user", "app", "global", "system"])
        )
    )

    # Outputs
    #   result:     created, updated (merge), deleted
    #
    #   content:    The dictionary containing the values
    #   token:      Splunk auth token (for subsequent call?)
    if not HAVE_SPLUNK_SDK:
        module.fail_json(msg='splunk-sdk required for this module')

    srConf = SplunkRestConf(module)
    p = module.params

    if not ((p["username"] and p["password"]) or p["token"]):
        module.fail_json(msg="%s requires either (1) 'username' and 'password' parameters, "
                             "or (2) token parameter for Splunkd authentication" % (MODULE_NAME,))

    try:
        srConf.connectUri(p['splunkd_uri'], p['username'],
                          p['password'], p['token'],
                          p["owner"], p["app"], p["sharing"])
    except Exception as e:
        module.fail_json(msg="Unable to connect to splunkd.  Exception: %s" % e)

    if p["state"] == "present":
        if not p["settings"]:
            module.fail_json(msg="Parameter 'settings' is required for state=present.")
        output = srConf.applySettings(p['conf'], p['stanza'],
                                      p['settings'], p['defaults'])
    elif p["state"] == "absent":
        output = srConf.deleteSettings(p['conf'], p['stanza'])
    elif p["state"] == "list":
        output = srConf.listSettings(p['conf'], p['stanza'])
    else:
        module.fail_json(msg="Unsupported state of '%s'" % p["state"])

    output["restarted"] = False
    if p["restart_on_change"] and output.get("changed", False):
        srConf.service.restart(p["restart_timeout"])
        output["restarted"] = True

    # For convenience, pass along some of the input parameters
    output["conf"] = p["conf"]
    output["stanza"] = p["stanza"]
    # Add auth 'token' which can be used for subsequent calls in the same play.
    output["token"] = srConf.getToken()
    # DEBUG, or is this worth keeping?
    output["params"] = p
    module.exit_json(**output)


if __name__ == '__main__':
    main()
