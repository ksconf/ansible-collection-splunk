# -*- coding: utf-8 -*-
#
# MODULE:  (This runs on the target node)
#
from __future__ import absolute_import, division, print_function

import json
import os
import time
from collections import defaultdict
from pathlib import Path, PurePath

from ansible.module_utils._text import to_bytes, to_native
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cdillc.splunk.plugins.module_utils.ksconf_shared import (
    SIDELOAD_STATE_FILE, __version__ as collection_version,
    check_ksconf_version)


__metaclass__ = type

ksconf_min_version = (0, 11)
ksconf_warn_version = (0, 11, 5)

ksconf_min_version_text = ".".join(f"{i}" for i in ksconf_min_version)
ksconf_warn_version_text = ".".join(f"{i}" for i in ksconf_warn_version)


DOCUMENTATION = r'''
---
module: ksconf_app_sideload
short_description: Unpacks a Splunk app archive after copying it from the controller machine
version_added: '0.10.0'
author: Lowell C. Alleman (@lowell80)
description:
     - By default, it will copy the source file from the local system to the target before unpacking.
     - For Windows targets, switch to Linux.
requirements:
  - ksconf>=0.11

options:
  src:
    description:
      - Local path to Splunk archive file to copy to the target server; can be absolute or relative.
    type: path
    required: true
  dest:
    description:
      - Remote absolute path where the archive should be unpacked.
      - Typically this will be C(/opt/splunk/etc/apps) or a management folder like C(deployment-apps),
        C(manager-apps) (or C(master-apps) pre Splunk 9.0), or C(shcluster/apps).
    type: path
    required: true
  state_file:
    description:
      - Override the default state file location.
        The default state file location is nested immediately under the app folder, called C(.ksconf_sideload.json).
      - Sometimes this may not be ideal when populating C(deployment-apps) where a single change could trigger a burst
        of traffic, or C(shcluster/apps) where looking at the manifest on the SHC members is always off (because local
        is merged to default behavior).
      - Be sure you understand the implications of changing this path.
        There must be one exactly state file per app per target, otherwise you can anticipate "flapping" between states
        as app deployment executes.
    type: path
    required: false
  recreate_manifest:
    description:
      - Allow remote rebuilding of corrupted or missing manifest state data.
      - This can be beneficial when upgrading between versions of the collection.
        But this may not be desirable in all situations. For example, any files not in new app will
        be removed, which can be problematic if you've intensionally created content within an app
        (e.g., you've deployed to the 'apps' folder of a running search head and allowed users to
        create/edit knowledge objects)
      - When disabled, any app update from earlier versions will simply overwrite the current
        content, leaving any unknown files as-is.  This means that previously deleted content will
        remain also means that previously delete content will not be removed, as file deletions were
        not supported prior to manifest support.
    type: bool
    default: true
    required: false
  io_buffer_size:
    description:
      - Size of the volatile memory buffer that is used for extracting files from the archive in bytes.
    type: bytes
    default: 65536
  list_files:
    description:
      - If set to True, return the list of files that are contained in the tarball.
    type: bool
    default: no
    version_added: "2.0"
#  exclude:
#    description:
#      - List the directory and file entries that you would like to exclude from the unarchive action.
#      - Mutually exclusive with C(include).
#    type: list
#    default: []
#    elements: str
#    version_added: "2.1"
#  include:
#    description:
#      - List of directory and file entries that you would like to extract from the archive. If C(include)
#        is not empty, only files listed here will be extracted.
#      - Mutually exclusive with C(exclude).
#    type: list
#    default: []
#    elements: str
#    version_added: "2.11"

extends_documentation_fragment:
    - action_common_attributes
    - action_common_attributes.flow
    - action_common_attributes.files
    - decrypt
    - files
attributes:
    action:
      support: full
    async:
      support: none
    bypass_host_loop:
      support: none
    check_mode:
      support: none
#    diff_mode:
#      support: partial
#      details: Uses gtar's C(--diff) arg to calculate if changed or not. If this C(arg) is not supported,
#               it will always unpack the archive.
    platform:
      platforms: posix
    safe_file_operations:
      support: none
    vault:
      support: full

notes:
    - Requires ksconf package on controller and target host.
    - Can handle I(.tgz), I(.tar.gz), I(.spl), and I(.zip) files.
    - Existing files/directories in the destination which are not in the archive
      are removed.  This requires that the prior app installation include a manifest.
      This feature was added in v0.18 of this collection; and all hash calculations have changed.
    - Note that only I(files) are extracted.
      This means empty directories will not be created.
      If this cause an issue for you, open a bug report and describe your use case.
    - Too speed up subsequent calls to I(ksconf_app_sideload), manifest files are created and cached
      on the controller node in the same directory as I(src).
      This reduces the controller's processing overhead.
      For this speedup to work, the controller must have write access to the
      parent directory of I(src).
      Also, any tarball created with I(ksconf_package) will already have this manifest file.
'''


EXAMPLES = r'''
- name: Extract ta-nix.tgz into /opt/splunk/etc/apps
  cdillc.splunk.ksconf_app_sideload:
    src: ta-nix.tgz
    dest: /opt/splunk/etc/apps

- name: Install rendered apps from version control & existing tarballs
  cdillc.splunk.ksconf_app_sideload:
    # Add prefix for archived apps
    src: "{{ apps_folder }}/{{ item }}"
    dest: "{{ splunk_home }}/etc/deployment-apps"
    owner: "{{ splunk_nix_user }}"
    group: "{{ splunk_nix_group }}"
  # Loop over present + managed apps created from (1) ksconf_package and (2) existing tarballs
  loop: >
    {{ app_render_output.results
      | selectattr("archive")
      | selectattr("item.state", "eq", "present")
      | selectattr("item.managed")
      | map(attribute="archive")
      + apps_inventory
      | selectattr("tarball")
      | selectattr("state", "eq", "present")
      | selectattr("managed")
      | map(attribute="tarball")
    }}
  become: true
  become_user: "{{ splunk_nix_user }}"
  notify: "reload deployment-server"
  tags: install
'''


RETURN = r'''
dest:
  description: Path to the destination directory.
  returned: always
  type: str
  sample: /opt/software
files:
  description: List of all the files in the archive.
  returned: When I(list_files) is True
  type: list
  sample: '["file1", "file2"]'
gid:
  description: Numerical ID of the group that owns the destination directory.
  returned: always
  type: int
  sample: 1000
group:
  description: Name of the group that owns the destination directory.
  returned: always
  type: str
  sample: "librarians"
mode:
  description: String that represents the octal permissions of the destination directory.
  returned: always
  type: str
  sample: "0755"
owner:
  description: Name of the user that owns the destination directory.
  returned: always
  type: str
  sample: "paul"
src:
  description:
    - The source archive's path.
    - The location is local to the ansible controller.
  returned: always
  type: str
  sample: "/home/paul/test.tar.gz"
state:
  description: State of the destination. Effectively always "directory".
  returned: always
  type: str
  sample: "directory"
state_file:
  description: >
    Path to the json state tracking file where installation state, source hash, and application manifest is stored.
    By default, this is relative to the app install path.
  returned: always
  type: str
  sample: fire_brigade/.ksconf_sideload.json
uid:
  description: Numerical ID of the user that owns the destination directory.
  returned: always
  type: int
  sample: 1000
'''


def calc_missing_parent_dirs(paths):
    """
    Given a sequence of paths, return a list of unique parent directories and
    files in tree creation order.
    """
    known_dirs = set()
    for path in paths:
        path = PurePath(path)
        assert not path.is_absolute(), f"Path {path} is not a relative path!"
        parent = path.parent
        while parent not in known_dirs:
            known_dirs.add(parent)
            parent = parent.parent
    return [os.fspath(p) for p in list(known_dirs) + paths]


def ksconf_sideload_app(src, dest, *, src_orig=None, state_file=None):
    try:
        from ksconf.version import version as ksconf_version
    except ImportError:
        from ksconf._version import version as ksconf_version
    from ksconf.app import get_facts_manifest_from_archive
    from ksconf.app.deploy import DeployActionType, DeployApply as DeployApplyBase, DeploySequence
    from ksconf.app.manifest import AppManifest

    src = Path(src)
    dest = Path(dest)

    class DeployApply(DeployApplyBase):
        def resolve_source(self, source, hash):
            # For right now, we only are dealing with a *single* app, so just always return 'src'
            return src

    deployer = DeployApply(dest)

    app_facts, app_manifest = get_facts_manifest_from_archive(src, calculate_hash=True,
                                                              check_paths=True)

    # Correct 'source' field to match the filename on the controller node
    app_manifest.source = src_orig or os.fspath(src)

    result = {
        # For legacy reasons, we are keeping "app_info" (may drop this in favor of app_conf below)
        "app_info": {
            "name": app_facts.name,
            "author": app_facts.author,
            "version": app_facts.version,
            "deprecated": "NOTE 'app_info' is going away, use 'app_facts' instead!",
        },
        # This is the new output that should be used
        "app_facts": app_facts.to_tiny_dict("name", "author", "version"),
    }

    # state file
    app_dir: Path = dest / app_manifest.name
    if state_file:
        # Normally this an absolute file; but relative is permitted
        state_file = app_dir / state_file
    else:
        state_file: Path = app_dir / SIDELOAD_STATE_FILE

    current_manifest = None
    if app_dir.is_dir():
        if state_file.is_file():
            try:
                data = json.loads(state_file.read_text())
                if "manifest" in data:
                    current_manifest = AppManifest.from_dict(data["manifest"])
                    manifest_msg = "manifest used for transformational update"
                else:
                    manifest_msg = "manifest missing from state file (upgrade?)"
                del data
            except (OSError, KeyError, ValueError) as e:
                manifest_msg = f"manifest unusable due to {type(e).__name__}: {e}"
        else:
            manifest_msg = "manifest missing"
    else:
        manifest_msg = "newly created manifest file (fresh app install)"
    seq = DeploySequence.from_manifest_transformation(current_manifest, app_manifest)

    # Need some kind of context manager here that (1) locks manifest file,
    # (2) Puts an in-progress marker in the manifest file so that we know the state is corrupted / interrupted.
    deployer.apply_sequence(seq)

    result["manifest_msg"] = manifest_msg

    # Don't rely on this to be stable.... more work to be done here.  Eventually want to report on what actually
    # happened, not just the deployment plan (sequence)
    files_changed = result["files_changed"] = defaultdict(list)
    result["file_change_counts"] = {}
    for type_, actions in seq.actions_by_type.items():
        type_ = str(type_)
        result["file_change_counts"][type_] = actions

    for action in seq.actions:
        if action.action in (DeployActionType.EXTRACT_FILE, DeployActionType.REMOVE_FILE):
            files_changed[str(action.action)].append(os.fspath(action.path))

    try:
        # Added in ksconf v0.11.5
        from ksconf.util.file import atomic_open
        f_context = atomic_open(state_file, mode="w", temp_name="tmp.sideload")
    except ImportError:
        f_context = open(state_file, "wb")

    with f_context as marker_f:
        data = {
            "src_path": src_orig or src,
            "src_hash": app_manifest.hash,
            "ansible_module_version": collection_version,
            "ksconf_version": ksconf_version,
            "installed_at": time.time(),
            "manifest": app_manifest.to_dict(),
        }
        json.dump(data, marker_f, indent=1)

    # Inventory paths are relative to the `dest` directory
    file_list = [app_manifest.name / f.path for f in app_manifest.files]
    # Remove non-existent paths (because manifest can be incorrect)
    file_list = [os.fspath(f) for f in file_list if (dest/f).is_file()]

    # Hard code this for now!
    result["changed"] = True
    return result, file_list, os.fspath(state_file)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            src=dict(type='path', required=True),
            src_orig=dict(type="path", required=False),  # Internal (added by action)
            dest=dict(type='path', required=True),
            state_file=dict(type='path', required=False),
            # show_manifest=dict(type=bool, default=False, alias="list_files")
            list_files=dict(type='bool', default=False)
        ),
        add_file_common_args=True,
        # supports_check_mode=True
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

    src = module.params['src']
    src_orig = module.params["src_orig"]
    state_file = module.params["state_file"]
    dest = module.params['dest']
    list_files = module.params["list_files"]
    b_dest = to_bytes(dest, errors='surrogate_or_strict')
    file_args = module.load_file_common_arguments(module.params)

    # did tar file arrive?
    if not os.path.exists(src):
        module.fail_json(msg="Source '%s' failed to transfer" % src)
    if not os.access(src, os.R_OK):
        module.fail_json(msg="Source '%s' not readable" % src)

    # skip working with 0 size archives
    try:
        if os.path.getsize(src) == 0:
            module.fail_json(msg="Invalid archive '%s', the file is 0 bytes" % src)
    except Exception as e:
        module.fail_json(msg="Source '%s' not readable, %s" % (src, to_native(e)))

    # is dest OK to receive tar file?
    if not os.path.isdir(b_dest):
        module.fail_json(msg="Destination '%s' is not a directory" % dest)

    if module.check_mode:
        module.exit_json(msg="Check mode unsupported....  Please finish the implementation!")

    res_args, files, state_file = ksconf_sideload_app(src, dest,
                                                      src_orig=src_orig,
                                                      state_file=state_file)

    if res_args.get('diff', True) and not module.check_mode:
        # Reset permissions on all files (mode,owner,group,attr,se*)

        # Only apply path changes if mode/owner/group was set
        if any(file_args.get(a, None) for a in ('mode', 'owner', 'group')):
            # Note:  Inject parent directories into the list as directories aren't in the manifest
            for filename in calc_missing_parent_dirs(files):
                file_args['path'] = os.path.join(b_dest, to_bytes(
                    filename, errors='surrogate_or_strict'))
                try:
                    res_args['changed'] = module.set_fs_attributes_if_different(
                        file_args, res_args['changed'], expand=False)
                except (IOError, OSError) as e:
                    module.fail_json(
                        msg=f"Unexpected error settings permissions for {filename}: {e}",
                        **res_args)

    if list_files:
        res_args["files"] = files

    res_args["state_file"] = state_file
    # DEBUG
    # res_args['check_results'] = check_results

    # Cleanup parameter to better match user's intention (Impacts the invocation/module_args output)
    module.params["src"] = src_orig
    del module.params["src_orig"]

    '''
    if module.check_mode:
        res_args['changed'] = not check_results['unarchived']
    elif check_results['unarchived']:
        res_args['changed'] = False
    else:
        # do the unpack
        try:
            res_args['extract_results'] = handler.unarchive()
            if res_args['extract_results']['rc'] != 0:
                module.fail_json(msg="failed to unpack %s to %s" % (src, dest), **res_args)
        except IOError:
            module.fail_json(msg="failed to unpack %s to %s" % (src, dest), **res_args)
        else:
            res_args['changed'] = True
    # Get diff if required
    if check_results.get('diff', False):
        res_args['diff'] = {'prepared': check_results['diff']}

    '''

    module.exit_json(**res_args)


if __name__ == '__main__':
    main()
