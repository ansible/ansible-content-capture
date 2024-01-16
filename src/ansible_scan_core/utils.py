# -*- mode:python; coding:utf-8 -*-

# Copyright (c) 2022 IBM Corp. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import traceback
import subprocess
import requests
import hashlib
import yaml
import json
from filelock import FileLock
from copy import deepcopy
from tabulate import tabulate
from inspect import isclass
from importlib.util import spec_from_file_location, module_from_spec

import ansible_scan_core.logger as logger


def lock_file(fpath, timeout=10):
    if not fpath:
        return
    lockfile = get_lock_file_name(fpath)
    lock = FileLock(lockfile, timeout=timeout)
    lock.acquire()
    return lock


def unlock_file(lock):
    if not lock:
        return
    if not isinstance(lock, FileLock):
        return
    lock.release()


def remove_lock_file(lock):
    if not lock:
        return
    if not isinstance(lock, FileLock):
        return
    lockfile = lock.lock_file
    if not lockfile:
        return
    if not os.path.exists(lockfile):
        return
    os.remove(lockfile)


def get_lock_file_name(fpath):
    return fpath + ".lock"


def install_galaxy_target(target, target_type, output_dir, source_repository="", target_version=""):
    server_option = ""
    if source_repository:
        server_option = "--server {}".format(source_repository)
    target_name = target
    if target_version:
        target_name = f"{target}:{target_version}"
    logger.debug("exec ansible-galaxy cmd: ansible-galaxy {} install {} {} -p {} --force".format(target_type, target_name, server_option, output_dir))
    proc = subprocess.run(
        "ansible-galaxy {} install {} {} -p {} --force".format(target_type, target_name, server_option, output_dir),
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.stdout, proc.stderr


def install_github_target(target, output_dir):
    proc = subprocess.run(
        "git clone {} {}".format(target, output_dir),
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc.stdout


def get_download_metadata(typ: str, install_msg: str):
    download_url = ""
    version = ""
    if typ == "collection":
        for line in install_msg.splitlines():
            if line.startswith("Downloading "):
                download_url = line.split(" ")[1]
                version = download_url.split("-")[-1].replace(".tar.gz", "")
                break
    elif typ == "role":
        for line in install_msg.splitlines():
            if line.startswith("- downloading role from "):
                download_url = line.split(" ")[-1]
                version = download_url.split("/")[-1].replace(".tar.gz", "")
                break
    hash = ""
    if download_url != "":
        hash = get_hash_of_url(download_url)
    return download_url, version, hash


def get_installed_metadata(type, name, path, dep_dir=None):
    if dep_dir:
        dep_dir_alt = os.path.join(dep_dir, "ansible_collections")
        if os.path.exists(dep_dir_alt):
            dep_dir = dep_dir_alt
        parts = name.split(".")
        if len(parts) == 1:
            parts.append("dummy")
        dep_dir_target_path = os.path.join(dep_dir, parts[0], parts[1])
        download_url, version = get_installed_metadata(type, name, dep_dir_target_path)
        if download_url or version:
            return download_url, version
    download_url = ""
    version = ""
    galaxy_yml = "GALAXY.yml"
    galaxy_data = None
    if type == "collection":
        base_dir = "/".join(path.split("/")[:-2])
        dirs = os.listdir(base_dir)
        for dir_name in dirs:
            tmp_galaxy_data = None
            if dir_name.startswith(name) and dir_name.endswith(".info"):
                galaxy_yml_path = os.path.join(base_dir, dir_name, galaxy_yml)
                try:
                    with open(galaxy_yml_path, "r") as galaxy_yml_file:
                        tmp_galaxy_data = yaml.safe_load(galaxy_yml_file)
                except Exception:
                    pass
            if isinstance(tmp_galaxy_data, dict):
                galaxy_data = tmp_galaxy_data
    if galaxy_data is not None:
        download_url = galaxy_data.get("download_url", "")
        version = galaxy_data.get("version", "")
    return download_url, version


def get_collection_metadata(path: str):
    if not os.path.exists(path):
        return None
    manifest_json_path = os.path.join(path, "MANIFEST.json")
    meta = None
    if os.path.exists(manifest_json_path):
        with open(manifest_json_path, "r") as file:
            meta = json.load(file)
    return meta


def get_role_metadata(path: str):
    if not os.path.exists(path):
        return None
    meta_main_yml_path = os.path.join(path, "meta", "main.yml")
    meta = None
    if os.path.exists(meta_main_yml_path):
        with open(meta_main_yml_path, "r") as file:
            meta = yaml.safe_load(file)
    return meta


def escape_url(url: str):
    base_url = url.split("?")[0]
    replaced = base_url.replace("://", "__").replace("/", "_")
    return replaced


def escape_local_path(path: str):
    replaced = path.replace("/", "__")
    return replaced


def get_hash_of_url(url: str):
    response = requests.get(url)
    hash = hashlib.sha256(response.content).hexdigest()
    return hash


def split_name_and_version(target_name):
    name = target_name
    version = ""
    if ":" in target_name:
        parts = target_name.split(":")
        name = parts[0]
        version = parts[1]
    return name, version


def split_target_playbook_fullpath(fullpath: str):
    basedir = os.path.dirname(fullpath)
    if "/playbooks/" in fullpath:
        basedir = fullpath.split("/playbooks/")[0]
    target_playbook_path = fullpath.replace(basedir, "")
    if target_playbook_path[0] == "/":
        target_playbook_path = target_playbook_path[1:]
    return basedir, target_playbook_path


def split_target_taskfile_fullpath(fullpath: str):
    basedir = os.path.dirname(fullpath)
    if "/roles/" in fullpath:
        basedir = fullpath.split("/roles/")[0]
    target_taskfile_path = fullpath.replace(basedir, "")
    if not target_taskfile_path:
        return basedir, ""
    if target_taskfile_path[0] == "/":
        target_taskfile_path = target_taskfile_path[1:]
    return basedir, target_taskfile_path


def version_to_num(ver: str):
    if ver == "unknown":
        return 0
    # version string can be 1.2.3-abcdxyz
    ver_num_part = ver.split("-")[0]
    parts = ver_num_part.split(".")
    num = 0
    if len(parts) >= 1:
        if parts[0].isnumeric():
            num += float(parts[0])
    if len(parts) >= 2:
        if parts[1].isnumeric():
            num += float(parts[1]) * (0.001**1)
    if len(parts) >= 3:
        if parts[2].isnumeric():
            num += float(parts[2]) * (0.001**2)
    return num


def is_url(txt: str):
    return "://" in txt


def is_local_path(txt: str):
    if is_url(txt):
        return False
    if "/" in txt:
        return True
    if os.path.exists(txt):
        return True


def indent(multi_line_txt, level=0):
    lines = multi_line_txt.splitlines()
    lines = [" " * level + line for line in lines if line.replace(" ", "") != ""]
    return "\n".join(lines)


def show_all_kb_metadata(kb_meta_list):
    table = [("NAME", "VERSION", "HASH")]
    for meta in kb_meta_list:
        table.append((meta["name"], meta["version"], meta["hash"]))
    print(tabulate(table))


def diff_files_data(files1, files2):
    files_dict1 = {}
    for finfo in files1.get("files", []):
        ftype = finfo.get("ftype", "")
        if ftype != "file":
            continue
        fpath = finfo.get("name", "")
        hash = finfo.get("chksum_sha256", "")
        files_dict1[fpath] = hash

    files_dict2 = {}
    for finfo in files2.get("files", []):
        ftype = finfo.get("ftype", "")
        if ftype != "file":
            continue
        fpath = finfo.get("name", "")
        hash = finfo.get("chksum_sha256", "")
        files_dict2[fpath] = hash

    # TODO: support "replaced" type
    diffs = []
    for fpath, hash in files_dict1.items():
        if fpath in files_dict2:
            if files_dict2[fpath] == hash:
                continue
            else:
                diffs.append(
                    {
                        "type": "updated",
                        "filepath": fpath,
                    }
                )
        else:
            diffs.append(
                {
                    "type": "created",
                    "filepath": fpath,
                }
            )

    for fpath, hash in files_dict2.items():
        if fpath in files_dict1:
            continue
        else:
            diffs.append(
                {
                    "type": "deleted",
                    "filepath": fpath,
                }
            )

    return diffs


def show_diffs(diffs):
    table = [("NAME", "DIFF_TYPE")]
    for d in diffs:
        table.append((d["filepath"], d["type"]))
    print(tabulate(table))


def get_module_specs_by_ansible_doc(module_files: str, fqcn_prefix: str, search_path: str):
    if not module_files:
        return {}

    if search_path and fqcn_prefix:
        parent_path_pattern = "/" + fqcn_prefix.replace(".", "/")
        if parent_path_pattern in search_path:
            search_path = search_path.split(parent_path_pattern)[0]

    fqcn_list = []
    for module_file_path in module_files:
        module_name = os.path.basename(module_file_path)
        if module_name[-3:] == ".py":
            module_name = module_name[:-3]
        if module_name == "__init__":
            continue
        fqcn = module_name
        if fqcn_prefix:
            fqcn = fqcn_prefix + "." + module_name
        fqcn_list.append(fqcn)
    if not fqcn_list:
        return {}
    fqcn_list_str = " ".join(fqcn_list)
    cmd_args = [f"ansible-doc {fqcn_list_str} --json"]
    _env = os.environ.copy()
    _env["ANSIBLE_COLLECTIONS_PATH"] = search_path
    proc = subprocess.run(args=cmd_args, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=_env)
    if proc.stderr and not proc.stdout:
        logger.debug(f"error while getting the documentation for modules `{fqcn_list_str}`: {proc.stderr}")
        return ""
    wrapper_dict = json.loads(proc.stdout)
    specs = {}
    for fqcn in wrapper_dict:
        doc_dict = wrapper_dict[fqcn].get("doc", {})
        doc = yaml.safe_dump(doc_dict, sort_keys=False)
        examples = wrapper_dict[fqcn].get("examples", "")
        specs[fqcn] = {
            "doc": doc,
            "examples": examples,
        }
    return specs


def get_documentation_in_module_file(fpath: str):
    if not fpath:
        return ""
    if not os.path.exists(fpath):
        return ""
    lines = []
    with open(fpath, "r") as file:
        for line in file:
            lines.append(line)
    doc_lines = []
    is_inside_doc = False
    quotation = ""
    for line in lines:
        stripped_line = line.strip()

        if is_inside_doc and quotation and stripped_line.startswith(quotation):
            is_inside_doc = False
            break

        if is_inside_doc:
            if quotation:
                doc_lines.append(line)
            else:
                if "'''" in line:
                    quotation = "'''"
                if '"""' in line:
                    quotation = '"""'

        if stripped_line.startswith("DOCUMENTATION"):
            is_inside_doc = True
            if "'''" in line:
                quotation = "'''"
            if '"""' in line:
                quotation = '"""'
    return "\n".join(doc_lines)


def get_class_by_arg_type(arg_type: str):
    if not isinstance(arg_type, str):
        return None

    mapping = {
        "str": str,
        "list": list,
        "dict": dict,
        "bool": bool,
        "int": int,
        "float": float,
        # Ansible handles `path` as a string
        "path": str,
        "raw": any,
        # TODO: check actual types of the following
        "jsonarg": str,
        "json": str,
        "bytes": str,
        "bits": str,
    }

    if arg_type not in mapping:
        return None

    return mapping[arg_type]


def load_classes_in_dir(dir_path: str, target_class: type, base_dir: str = "", only_subclass: bool = True, fail_on_error: bool = False):
    search_path = dir_path
    found = False
    if os.path.exists(search_path):
        found = True
    if not found and base_dir:
        self_path = os.path.abspath(base_dir)
        search_path = os.path.join(os.path.dirname(self_path), dir_path)
        if os.path.exists(search_path):
            found = True

    if not found:
        raise ValueError(f'Path not found "{dir_path}"')

    files = os.listdir(search_path)
    scripts = [os.path.join(search_path, f) for f in files if f[-3:] == ".py"]
    classes = []
    errors = []
    for s in scripts:
        try:
            short_module_name = os.path.basename(s)[:-3]
            spec = spec_from_file_location(short_module_name, s)
            mod = module_from_spec(spec)
            spec.loader.exec_module(mod)
            for k in mod.__dict__:
                cls = getattr(mod, k)
                if not callable(cls):
                    continue
                if not isclass(cls):
                    continue
                if not issubclass(cls, target_class):
                    continue
                if only_subclass and cls == target_class:
                    continue
                classes.append(cls)
        except Exception:
            exc = traceback.format_exc()
            msg = f"failed to load a module {s}: {exc}"
            if fail_on_error:
                raise ValueError(msg)
            else:
                errors.append(msg)
    return classes, errors


def equal(a: any, b: any):
    type_a = type(a)
    type_b = type(b)
    if type_a != type_b:
        return False
    if type_a == dict:
        all_keys = list(a.keys()) + list(b.keys())
        for key in all_keys:
            val_a = a.get(key, None)
            val_b = b.get(key, None)
            if not equal(val_a, val_b):
                return False
    elif type_a == list:
        if len(a) != len(b):
            return False
        for i in range(len(a)):
            val_a = a[i]
            val_b = b[i]
            if not equal(val_a, val_b):
                return False
    elif hasattr(a, "__dict__"):
        if not equal(a.__dict__, b.__dict__):
            return False
    else:
        if a != b:
            return False
    return True


def recursive_copy_dict(src, dst):
    if not isinstance(src, dict):
        raise ValueError(f"only dict input is allowed, but got {type(src)}")

    if not isinstance(dst, dict):
        raise ValueError(f"only dict input is allowed, but got {type(dst)}")

    for k, sv in src.items():
        if isinstance(sv, dict):
            dst[k] = {}
            recursive_copy_dict(sv, dst[k])
        else:
            dst[k] = deepcopy(sv)
    return


def is_test_object(path: str):
    return path.startswith("tests/integration/") or path.startswith("molecule/")
