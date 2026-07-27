# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function


__metaclass__ = type

import os
import re
from contextlib import contextmanager
from pathlib import Path
from random import randint

from ansible.module_utils.basic import AnsibleModule


__version__ = "0.26.3"

SIDELOAD_STATE_FILE = ".ksconf_sideload.json"

# Traditional Splunk home (install paths)
SPLUNK_HOME_PATH = [
    "/opt/splunk",
    "/Applications/Splunk",
    "/opt/splunkforwarder"
]


def find_splunk_home():
    """ Find an appropriate value for SPLUNK_HOME.

    First, use $SPLUNK_HOME if that directory exists.  After that, try a series
    of path-based guesses based on common installation files, and finally just
    go with *any* match against the well known splunk home list.

    Multiple splunk installations are not explicitly supported.
    """
    if "SPLUNK_HOME" in os.environ:
        path = os.environ["SPLUNK_HOME"]
        if os.path.isdir(path):
            return path

    # Check popular paths
    for known_path in ("bin/splunk", "etc/splunk.version", None):
        path = _guess_splunk_home(SPLUNK_HOME_PATH, known_path)
        if path:
            return path
    return None


def _guess_splunk_home(discovery_paths, test_file):
    for path in discovery_paths:
        if os.path.isdir(path):
            if test_file:
                test_path = os.path.join(path, test_file)
                if os.path.isfile(test_path):
                    return path
            else:
                return path
    return None


def check_ksconf_version(module: AnsibleModule = None) -> tuple:
    if not module:
        from ansible.errors import AnsibleActionFail
        from ansible.utils.display import Display
        display = Display()
    try:
        # Public interface (finally!)  Added in ksconf v0.13.4
        from ksconf.version import version as ksconf_version
    except ImportError:
        try:
            # Try hitting the internal version (fallback for older versions)
            from ksconf._version import version as ksconf_version
        except ImportError:
            message = "Unable to import the 'ksconf' python module.  "\
                "Try running 'pip install -U ksconf'"
            if module:
                module.fail_json(msg=message)
            else:
                raise AnsibleActionFail(message=message)

    match = re.match(r'(\d+)\.(\d+)\.(\d+)(.*)$', ksconf_version)
    if match:
        p = match.groups()
        return int(p[0]), int(p[1]), int(p[2]), p[3]
    else:
        message = f"Unable to parse ksconf version.  '{ksconf_version}'"
        if module:
            module.warn(message)
        else:
            display.warning(message)
        return 0, 0, 0, ksconf_version


@contextmanager
def temp_decrypt(encrypted_file: Path, vault, *, clone_mtime=False, log_callback=None):
    from ansible.parsing.vault import VaultEditor
    from ksconf.util.file import secure_delete
    if log_callback is None:
        def log_callback(s): pass

    vault_editor = VaultEditor(vault)
    decrypted_file = encrypted_file.with_name(encrypted_file.name +
                                              f".decrypted-{os.getpid()}-{randint(0, 999999)}")
    assert not decrypted_file.is_file()
    log_callback(f"temp_decrypt:  Decrypting vault file {encrypted_file} -> {decrypted_file}")
    vault_editor.decrypt_file(encrypted_file, decrypted_file)
    if clone_mtime:
        stat = encrypted_file.stat()
        os.utime(decrypted_file, (stat.st_atime, stat.st_mtime))
    yield decrypted_file

    log_callback(f"temp_decrypt:  Removing decrypted file {decrypted_file}")
    secure_delete(decrypted_file)
