# -*- coding: utf-8 -*-
#
# MODULE:  (This runs on the target node)
#
"""

Eventually this module should be expanded to support:

1.) Fast hash check.   No need to return the entire payload if the hash matches on the target
2.) Check for differences.   Report which (if any) files vary from the known manifest.
3.) Check against an explicit manifest???  (needs more consideration)

"""

from __future__ import absolute_import, division, print_function

import json
import os
import time
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any, Tuple

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cdillc.splunk.plugins.module_utils.ksconf_shared import (
    SIDELOAD_STATE_FILE, __version__ as collection_version,
    check_ksconf_version)


try:
    from ksconf.version import version as ksconf_version
except ImportError:
    from ksconf._version import version as ksconf_version


if TYPE_CHECKING:
    from ksconf.app.manifest import AppManifest
else:
    AppManifest = Any


__metaclass__ = type

ksconf_min_version = (0, 11, 5)
ksconf_warn_version = (0, 13, 4)

ksconf_min_version_text = ".".join(f"{i}" for i in ksconf_min_version)
ksconf_warn_version_text = ".".join(f"{i}" for i in ksconf_warn_version)


DOCUMENTATION = r'''
---
module: ksconf_app_manifest
short_description: Splunk app manifest (Private)
version_added: '0.22.0'
author: Lowell C. Alleman (@lowell80)
description:
  - This is used internally by the M(cdillc.splunk.ksconf_app_sideload).
    This is not currently intended to be used directly by users.

requirements:
  - ksconf>=0.11

options:
  app_dir:
    description: Path to Splunk application
    type: path
    required: true
  state_file:
    description: Location of the state file
    type: path
    required: false
  rebuild_manifest:
    description: Rebuild the manifest information when missing from or corrupted with the state file.
    type: bool
    default: false
  discard_local_app_autogen:
    description:
        - Discard the auto generated C(local/app.conf) file created by the deployment server.
        - This requires ksconf v0.13.5, or this feature will be ignored.
    type: bool
    default: true

extends_documentation_fragment:
    - action_common_attributes

attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
  platform:
    platforms: posix

notes:
  - Requires ksconf on the target host.

'''


EXAMPLES = r'''
- name: Don't do this.  This module is not public
  cdillc.splunk.ksconf_app_manifest:
    app_dir: /opt/splunk/etc/apps/myapp
    state_file: /opt/splunk/etc/apps/myapp/.ksconf_sideload.json
'''


RETURN = r'''
app_dir:
  description:  Expanded application directory
  returned: always
  type: str
  sample: "/opt/splunk/etc/app/fire_brigade"

state_file:
  description: Relative path to the json state tracking file where installation state, source hash,
              and application manifest is stored.
  returned: always
  type: str
  sample: /opt/splunk/etc/app/fire_brigade/.ksconf_sideload.json

state_init:
  description:
    - Health indicator of first attempt at reading from I(present).
    - >
        Expect values such as:
    - C(present) - state present and includes manifest,
    - C(old-version) - state present with no manifest,
    - C(corrupted) - unable to decode json,
    - C(missing) - no state file present, or
    - C(error) unexpected error attempting to load I(state_file).
  returned: always
  type: str

result:
  description:
    - >
      Final status of the state file.  Values include:
    - C(loaded) when state & manifest successfully loaded from I(state_file),
    - C(created) when state file was created from scratch,
    - C(rebuilt) when existing state file was updated with new manifest, or
    - C(no-manifest) when the manifest could not be loaded and I(rebuild_manifest) is false.
    - >
      Any of the follows indicate a failure:
    - C(no-app) when the I(app_dir) is missing,
    - C(error) when an unexpected error occurred.
  type: str
  returned: always

manifest:
  description: >
    Manifest objects.
    See L(AppManifest,https://ksconf.readthedocs.io/en/latest/api/ksconf.app.html#ksconf.app.manifest.AppManifest)
  returned: when manifest is present or built
  type: dict

state:
  description: State of the state file / manifest
  returned: on success
  type: dict

'''


def get_app_manifest(state_file: Path) -> Tuple[AppManifest, dict, str]:
    from ksconf.app.manifest import AppManifest
    try:
        with open(state_file) as fp:
            try:
                state_data = json.load(fp)
            except ValueError:
                # Or json.decoder.JSONDecodeError?
                return None, None, "corrupted"
            if "manifest" in state_data:
                return AppManifest.from_dict(state_data.pop("manifest")), state_data, "present"
            else:
                return None, state_data, "old-version"
    except FileNotFoundError:
        return None, None, "missing"


def build_app_manifest(app_dir: Path, state_file: Path,
                       discard_local_app_autogen=True) -> AppManifest:
    """ Build a new app manifest for an existing app directory. """
    from ksconf.app.manifest import AppManifest

    if state_file.exists():
        try:
            rel_statefile = state_file.relative_to(app_dir)
            def filter_state_file(path): return path != rel_statefile
        except ValueError:
            # State file not stored within the app directory.  Nothing to filter out
            # NOTE: Can't use is_relative_to(); added in Python 3.9, still supporting 3.8
            filter_state_file = None
    else:
        # No existing state file; nothing to filter (other deployment mechanism, or alternate state_file location?)
        filter_state_file = None

    try:
        # Ksconf v0.13.4 adds 'filter_file' argument
        manifest = AppManifest.from_filesystem(app_dir, calculate_hash=True,
                                               filter_file=filter_state_file)
    except TypeError:
        # Older ksconf.  Simply move manifest up a directory and restore when done.
        try:
            if state_file.exists():
                temp_state = app_dir.parent.joinpath(f".{app_dir.name}.ksconf-manifest-rebuild.tmp")
                state_file.replace(temp_state)
            else:
                temp_state = None
            manifest = AppManifest.from_filesystem(app_dir, calculate_hash=True)
        finally:
            if temp_state:
                temp_state.replace(state_file)

    if discard_local_app_autogen:
        with suppress(AttributeError):
            manifest.drop_ds_autogen()

    return manifest


def write_app_state(state_file: Path,
                    app_manifest: AppManifest,
                    existing_state: dict = None):
    from ksconf.util.file import atomic_open
    if existing_state:
        data = existing_state.copy()
    else:
        data = {}

    data.setdefault("src_path", None)
    data.setdefault("installed_at", time.time())
    data.update(src_hash=app_manifest.hash,
                ansible_module_version=collection_version,
                ksconf_version=ksconf_version,
                manifest=app_manifest.to_dict())
    data["rebuilt_from_filesystem"] = True
    with atomic_open(state_file, mode="w", temp_name="tmp.sideload") as marker_f:
        json.dump(data, marker_f, indent=1)
    return data


def main():
    module = AnsibleModule(
        argument_spec=dict(
            app_dir=dict(type='path', required=True),
            state_file=dict(type="path", required=False),
            rebuild_manifest=dict(type=bool, default=False),
            discard_local_app_autogen=dict(type=bool, default=True),
            raise_exception=dict(type=bool, default=False),        # Undocumented.  For internal debugging
        ),
        supports_check_mode=False,
    )

    ksconf_version = check_ksconf_version(module)
    if ksconf_version < ksconf_min_version:
        module.fail_json(
            msg=f"ksconf version {ksconf_version} is older than {ksconf_min_version_text}.  "
            "This may result in unexpected behavior.  Please upgrade ksconf to "
            f"{ksconf_warn_version_text} or higher.  Please run:  \n"
            "    ansible-playbook cdillc.splunk.install_dependencies -e splunk_host=all")
    if ksconf_version < ksconf_warn_version:
        # It *should* still work, but your milage may vary
        module.warn(f"ksconf version {ksconf_version} is older than {ksconf_warn_version_text}.")

    app_dir = Path(module.params['app_dir'])
    state_file = module.params["state_file"]
    rebuild_manifest = module.params['rebuild_manifest']
    raise_exception = module.params["raise_exception"]
    discard_local_app_autogen = module.params["discard_local_app_autogen"]

    if state_file:
        state_file = Path(state_file)
    else:
        state_file = app_dir / SIDELOAD_STATE_FILE

    if module.check_mode:
        module.exit_json(msg="Check mode unsupported....  Please finish the implementation!")

    results = {
        "app_dir": os.fspath(app_dir),
        "state_file": os.fspath(state_file),
    }
    if not app_dir.is_dir():
        module.fail_json(msg=f"App directory {app_dir} does not exists", result="no-app", **results)
    if not os.access(app_dir, os.R_OK):
        module.fail_json(msg=f"App directory {app_dir} is not readable", result="no-app", **results)

    manifest = state = None
    try:
        # Is the state_file missing (only a problem if rebuild_manifest is not present)
        manifest, state, results["state_init"] = get_app_manifest(state_file)
    except Exception as e:
        results["state_init"] = "error"
        module.warn(f"Unexpected exception during get_app_manifest(): {type(e).__name__}: {e}")
        if raise_exception:
            raise e

    if manifest:
        results["result"] = "loaded"
    else:
        if rebuild_manifest:
            # Attempt to build a new manifest

            prev_mod_version = state.get('ansible_module_version', '?')
            try:
                manifest = build_app_manifest(app_dir, state_file, discard_local_app_autogen)
                state = write_app_state(state_file, manifest, state)
                results["changed"] = True
            except Exception as e:
                results["result"] = "error"
                module.fail_json(msg=f"Failed to build state file {state_file} ({results['state_init']}) "
                                 f"from app {app_dir} due to exception: {type(e).__name__}: {e}", **results)
                if raise_exception:
                    raise e
                return

            if results["state_init"] == "old-version":
                module.warn(f"Built new manifest due to version upgrade.  "
                            f" {prev_mod_version} -> {collection_version}")
            else:
                module.warn(f"Built new manifest.  Previous state file was {results['state_init']}")

            if results["state_init"] == "missing":
                results["result"] = "created"
            else:
                results["result"] = "rebuilt"
        else:
            # No manifest information present; and rebuild is prohibited
            results["result"] = "no-manifest"

    results["state"] = state
    if manifest:
        results["manifest"] = manifest.to_dict()

    module.exit_json(**results)


if __name__ == '__main__':
    main()
