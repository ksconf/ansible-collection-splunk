#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

import hashlib
import json
import os
import re
from pathlib import Path

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cdillc.splunk.plugins.module_utils.ksconf_shared import (
    SIDELOAD_STATE_FILE, find_splunk_home)


__metaclass__ = type


DOCUMENTATION = r'''
---
module: splunk_facts
short_description: Gathers facts about a Splunk installation
version_added: "0.10.0"
author: Lowell C. Alleman (@lowell80)

extends_documentation_fragment:
    - action_common_attributes.facts

attributes:
    facts:
        support: full

options:
    splunk_home:
        description:
            - Path to Splunk installation path. If not provided, this
              module will check the $SPLUNK_HOME environment variable
              and then several commonly used install paths.
            - Can also be set to I(skip) to disable normal Splunk information
              collection.  Useful in Splunk-detached cases, like app dir scans.
        required: false
        type: path
        default: null
    ksconf:
        description:
            - Set the level of ksconf detail to collect.
            - Use I(skip) to disable all ksconf related facts,
              I(short) to collect basic information,
              and I(detail) to show information about the available subcommands.
        choices: ["skip", "short", "detail"]
        type: str
        required: false
        default: short
    app_dirs:
        description:
            - List of paths (relative to I($SPLUNK_HOME/etc)).
            - An absolute path can be provided to check a specific path.
            - An empty list C([]) can be provided to disable app inventory collection.
        type: list
        required: false
        elements: str
        default: [apps, deployment-apps, shcluster/apps, manager-apps, peer-apps, master-apps, slave-apps]

description:
    - This module collects various pieces of data about a Splunk installation.
    - Splunk apps data collection.
notes:
    - Parameters to enable/disable various config or run-time stats may be added later.
'''

EXAMPLES = r'''
- name: Gather facts about the local Splunk install
  cdillc.splunk.splunk_facts:

- name: Gather facts for a custom Splunk install home
  cdillc.splunk.splunk_facts:
    splunk_home: /opt/acmeco/splunk

- name: Gather Splunk app facts from a git repository without a local SPLUNK_HOME
  cdillc.splunk.splunk_facts:
    app_dirs:
      - /opt/git-repo/apps
    splunk_home: skip
'''

RETURN = r'''
ansible_facts:
  description: Splunk facts
  type: dict
  contains:
    ansible_splunk_version:
      description: >
        Version of the Splunk software found
      type: dict
      returned: always
      contains:
        version:
          description: Splunk version string from C(etc/splunk.version).
          type: str
          sample: 9.0.4
        build:
          description: Splunk build number from C(etc/splunk.version).
          type: int
        product:
          description: Splunk product name from C(etc/splunk.version).
          type: str
        platform:
          description: Splunk platform identifier from C(etc/splunk.version).
          type: str

    ansible_splunk_dist_search:
      description: Distributed search public key details.
      type: dict
      contains:
        server_public_key:
          description: Contents of the trusted distributed search public key file.
          type: str

    ansible_splunk_config:
      description: Splunk configs.
      type: dict
      sample:
        <config>:
          <stanza>:
            <key>: value

    ansible_splunk_launch:
      description:
        - Splunk's startup configuration files located in C(splunk-launch.conf).
        - The exact keys located here will vary based on which settings are present.
          Contents shown here are based on popular settings.
      type: dict
      contains:
        SPLUNK_SERVER_NAME:
          description: Local server's name.  Popular values include C(Splunkd) and C(SplunkForwarder)
          type: str
        SPLUNK_DB:
          description: Default path to splunk indexes.
          type: str
        SPLUNK_OS_USER:
          description: Name of the user Splunk runs as.
          type: str
        PYTHONHTTPSVERIFY:
          description: Whether Splunk's embedded Python verifies HTTPS certificates.
          type: str

    ansible_splunk_swid:
      description: Software id tags
      type: dict
      contains:
        name:
          description:
            - Software name.  Examples include C(Splunk Enterprise) and C(UniversalForwarder).
          type: str
          sample: UniversalForwarder
        version:
          description: Software identity version from the SWID tag.
          type: str
        patch:
          description: Software identity patch level from the SWID tag, when present.
          type: str

    ansible_splunk_ksconf:
      description: ksconf version information
      returned: when requested
      type: dict
      contains:
        version:
          description: Installed ksconf version string.
          type: str
        vcs_info:
          description: Optional VCS metadata for the installed ksconf package.
          # Double check on this. could be a tuple?
          type: str
        build:
          description: ksconf build number, when available.
          type: int
        package:
          description: Python distribution/package name for ksconf.
          type: str
        path:
          description: Filesystem path to the installed ksconf package.
          type: str
        commands:
          description: Inventory of available ksconf subcommands when I(ksconf=detail).
          type: dict
          contains:
            <command>:
              description:
                - The key I(<command>) is dynamically set for each sub-command of the ksconf tool.
              sample: xml-format
              type: dict
              contains:
                class:
                  description: class name
                  type: str
                distro:
                  description: Distribution or entry-point source for the subcommand.
                  type: str
                error:
                  description:
                    - Any errors related to specific ksconf commands.
                    - This can happen for example if some Python modules are missing such as I(lxml) or I(splunksdk).
                  type: str
                  returned: on error

    ansible_splunk_apps:
      description:
        - A list of Splunk apps found.
        - Collection is restricted to the given set of apps in one of the provided I(app_dirs).
      type: list
      elements: dict
      contains:
        name:
          description: Folder name of the Splunk app
          type: str
          returned: always
        root:
          description: app location prefix (based on the given value of I(app_dirs))
          type: str
          sample: deployment-apps
          returned: always
        path:
          description: Full path to Splunk application.  This will uniquely identify an app.
          type: str
          returned: always
        app_conf:
          description:
            - Configuration information extracted from C(app.conf).
            - Only attributes present will be returned, unless otherwise noted.
            - Data types noted below are based on normal app conventions.
              However, if the app provides unexpected values (like a non-integer C(build)), that
              value is passed along as-is and therefore may be of another type.
          type: dict
          returned: always
          contains:
            version:
              description: App version from C(app.conf).
              type: str
              returned: always
            author:
              description: App author from C(app.conf).
              type: str
              returned: always
            description:
              description: Longer description contained with the app.
                           (This is not typically shown anywhere in the UI)
              type: str
            state:
              description: App enabled/disabled state from C(app.conf), when present.
              type: str
            build:
              description: App build number from C(app.conf), when present.
              type: int
            check_for_updates:
              description: Whether the app checks for updates, when present.
              type: bool
            label:
              description: Display name
              type: str
            is_visible:
              description: Is the app visible in the user interface
              type: bool
        sideload:
          type: dict
          returned: Only present if the app was installed via I(ksconf_sideload_app) module.
          description:
            - Data loaded is dependent upon the version of ksconf and the sideload module.
            # Check to see if this is still accurate as of v0.18+ of this module
          contains:
            ansible_module_version:
              description: Version of the sideload module that recorded the install state.
              type: str
            installed_at:
              description: Timestamp of when the app was sideloaded.
              type: str
            src_hash:
              description: Hash of the source package used for the sideload install.
              type: str
            src_path:
              description: Source path of the package used for the sideload install.
              type: str

    ansible_splunk_app_root_missing:
      description:
        - App paths that were inaccessible and therefore are not listed in I(ansible_splunk_apps).
      type: list
      elements: str
'''

SPLUNK_VERSION = "etc/splunk.version"
SPLUNK_INSTANCE_CFG = "etc/instance.cfg"
SPLUNK_LAUNCH_CONF = "etc/splunk-launch.conf"
SPLUNK_AUTH_SECRET = "etc/auth/splunk.secret"
SPLUNK_DIST_SEARCH_PUB_KEY = "etc/auth/distServerKeys/trusted.pem"
SPLUNK_APP_DIRS = [
    "apps",
    "deployment-apps",
    "shcluster/apps",
    "manager-apps",
    "peer-apps",
    # Drop these after 8.x support is fully gone (Not before 2025)
    "master-apps",
    "slave-apps",
]


class SplunkMetadata(object):
    def __init__(self, module, splunk_home=None, ksconf_level="short",
                 app_dirs=()):
        self.module = module
        if not splunk_home:
            splunk_home = find_splunk_home()
            if not splunk_home:
                self.fail("Couldn't locate SPLUNK_HOME.")
                return
        if splunk_home == "skip":
            # Special case where only apps dir or ksconf bits are evaluated
            self.splunk_home = None
        else:
            self.splunk_home = Path(splunk_home)
        self._fail = False
        self._error = []
        self._data = {}
        self._prefix = 'ansible_splunk_%s'
        if self.splunk_home:
            self.fetch_version()
            self.fetch_dist_search_keys()
            self.fetch_guid()
            self.fetch_swid()
            self.fetch_launch_vars()
            self.fetch_splunksecret()
        if ksconf_level != "skip":
            self.fetch_ksconf_version(ksconf_level)
        for app_dir in app_dirs:
            self.fetch_app_info(Path(app_dir))

    def error(self, msg):
        self._error.append(msg)

    def fail(self, msg):
        self.error(msg)
        self._fail = True

    def fetch_version(self):
        splunk_version = self.splunk_home / SPLUNK_VERSION
        sv = {}
        try:
            for line in open(splunk_version):
                line = line.strip()
                if line and "=" in line:
                    (key, value) = line.strip().split("=", 1)
                    sv[key.lower()] = value
            self._data["version"] = sv
        except Exception:
            self.fail("Unable to get version info from file:  %s" % splunk_version)

    def fetch_launch_vars(self):
        launch: Path = self.splunk_home / SPLUNK_LAUNCH_CONF
        launch_vars = {}
        try:
            text = launch.read_text()
            for match in re.finditer(r'(?:^|[\r\n]+)([A-Z_]+)=([^\r\n]+)', text):
                key, value = match.groups()
                launch_vars[key] = value
        except Exception as e:
            self.error(f"Unable to load launch values from {launch} due to exception: {e}")
        if launch_vars:
            self._data["launch"] = launch_vars

    def fetch_swid(self):
        # Use regex here to avoid dealing with XML libraries for this very basic structure
        swid = {}
        for p in self.splunk_home.glob("swidtag/*.swidtag"):
            try:
                swid["_source"] = str(p)
                match = re.search(r'<SoftwareIdentity (.*?)/?>', p.read_text())
                if match:
                    text = match.group(1)
                    # TODO: support both double and single quotes....
                    for match in re.finditer(r'\b([\w:]+)="([^"]*)"', text):
                        tag, value = match.groups()
                        swid[tag] = value
            except Exception as e:
                self.error(f"Unable to load launch values from {p} due to exception: {e}")
        if swid:
            self._data["swid"] = swid

    def fetch_dist_search_keys(self):
        # NOTE:  To get the correct path, we need to do something like:
        #           btool distsearch list tokenExchKeys
        #       and then parse for "certDir" and "publicKey" values.
        #       But we're just starting with the static default path.
        pub_key_path: Path = self.splunk_home / SPLUNK_DIST_SEARCH_PUB_KEY
        try:
            pub_key = pub_key_path.read_text()
            self._data["dist_search"] = dict(server_public_key=pub_key)
        except Exception:
            self.error("Unable to read distributed search public key: %s" % pub_key_path)

    def fetch_guid(self):
        # Only looking in the Splunk 6.x location (skipping server.conf)
        cfg_file = self.splunk_home / SPLUNK_INSTANCE_CFG
        try:
            for line in open(cfg_file):
                mo = re.match(r"^guid\s*=\s*([A-Fa-f0-9-]+)\s*$", line)
                if mo:
                    self._data["guid"] = mo.group(1)
                    return
        except Exception:
            self.error("Unable to read guid from file: %s" % cfg_file)

    def fetch_splunksecret(self):
        fn: Path = self.splunk_home / SPLUNK_AUTH_SECRET
        try:
            # Note could use module.sha1(filename) instead ....
            h = hashlib.new("sha256")
            h.update(fn.read_bytes())
            self._data["secret_hash"] = h.hexdigest()
        except Exception as e:
            self.error(f"Unable to read secret file: {fn}  Exception={e}")

    def fetch_ksconf_version(self, level):
        try:
            try:
                import ksconf.version as ksconf
                ksconf.version  # Workaround for v0.13.3, which only has__version__
            except (ImportError, AttributeError):
                # Prior to v0.13.4
                import ksconf._version as ksconf
            self._data["ksconf"] = {
                "version": ksconf.version,
                "version_info": getattr(ksconf, "version_info", []),    # Added in v0.13.4
                "vcs_info": ksconf.vcs_info,
                "build": ksconf.build,
                "package": ksconf.__package__,
                "path": os.path.dirname(os.path.abspath(ksconf.__file__)),
            }
        except ImportError:
            self._data["ksconf"] = None
            self.error("Unable to locate ksconf python module")
            return

        if level != "detail":
            return

        try:
            try:
                # ksconf v0.13 ( 'ksconf.commands' is now a namespace)
                from ksconf.command import get_all_ksconf_cmds
            except ImportError:
                # ks
                from ksconf.commands import get_all_ksconf_cmds
            self._data["ksconf"]["commands"] = subcommands = {}
            for ep in get_all_ksconf_cmds(on_error="return"):
                # (name, entry, cmd_cls, error)
                dist = ep.entry.dist
                distro = ""
                if hasattr(dist, "version"):
                    if hasattr(dist, "name"):
                        # entrypoints (required by ksconf)
                        distro = "{}  ({})".format(dist.name, ep.entry.dist.version)
                    elif hasattr(dist, "location") and hasattr(dist, "project_name"):
                        # Attributes per pkg_resource
                        distro = "{}  ({})  @{}".format(dist.project_name,
                                                        dist.version, dist.location)
                subcommands[ep.name] = {
                    "class": str(ep.cmd_cls.__name__),
                    "distro": distro,
                    "error": ep.error
                }
        except ImportError:
            self.error("Unable to report ksconf subcommands inventory")

    def fetch_app_info(self, app_root: Path, max_manifest_length=30):
        # Classic LIST of DICT question... not sure which is better
        app_facts = self._data.setdefault("apps", [])
        _app_root = app_root

        # If a relative path is given, assume it's relative to $SPLUNK_HOME/etc
        if not app_root.is_absolute():
            if not self.splunk_home:
                self.error("Cannot handle relative app_dir of '%s' when splunk_home is not set" % app_root)
                return
            app_root = Path(self.splunk_home) / "etc" / app_root

        if not app_root.is_dir():
            self._data.setdefault("app_root_missing", []).append(os.fspath(app_root))
            return

        for app_name in os.listdir(app_root):
            app_path = app_root / app_name
            if not app_path.is_dir():
                continue
            info = {
                "name": app_name,
                "root": os.fspath(_app_root),
                "path": os.fspath(app_path)
            }

            collect_appconf = self._data["ksconf"] is not None

            try:
                if collect_appconf:
                    from ksconf.app.facts import AppFacts
                    af = AppFacts.from_app_dir(app_path)
                    info["app_conf"] = af.to_tiny_dict("name", "author", "version")
                    del af

                if True:
                    state_file = app_path / SIDELOAD_STATE_FILE
                    if state_file.is_file():
                        with open(state_file) as fp:
                            data = json.load(fp)
                        try:
                            if len(data["manifest"]["files"]) > max_manifest_length:
                                data["manifest"]["files"] = len(data["manifest"]["files"])
                        except KeyError:
                            pass
                        except (ValueError, KeyError, TypeError) as e:
                            data["a_thing_that_happened"] = str(e)

                        info["sideload"] = data

            except ValueError as e:
                self.error(f"{e}")

            app_facts.append(info)

    def return_facts(self):
        if self._fail:
            return dict(failed=True, msg="\n".join(self._error))
        sf = {}
        if self.splunk_home:
            sf[self._prefix % "home"] = os.fspath(self.splunk_home)
        for (key, value) in self._data.items():
            sf[self._prefix % key] = value
        if self._error:
            sf["msg"] = "\n".join(self._error)
        return dict(changed=False, ansible_facts=sf)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            splunk_home=dict(required=False, default=None),
            ksconf=dict(type="str",
                        choices=["skip", "short", "detail"],
                        default="short"),
            app_dirs=dict(type="list",
                          elements="str",
                          required=False,
                          default=SPLUNK_APP_DIRS)
        ),
        supports_check_mode=True
    )

    # Parameters
    splunk_home = module.params['splunk_home']
    ksconf_level = module.params["ksconf"]
    app_dirs = module.params["app_dirs"]

    splunk_facts = SplunkMetadata(module,
                                  splunk_home=splunk_home,
                                  ksconf_level=ksconf_level,
                                  app_dirs=app_dirs)
    output = splunk_facts.return_facts()
    module.exit_json(**output)


if __name__ == '__main__':
    main()
