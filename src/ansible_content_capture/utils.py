# -*- mode:python; coding:utf-8 -*-

# Copyright (c) 2024 IBM Corp. All rights reserved.
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
import re
import traceback
import subprocess
import requests
import hashlib
import yaml
import json
import codecs
from filelock import FileLock
from copy import deepcopy
from tabulate import tabulate
from inspect import isclass
from importlib.util import spec_from_file_location, module_from_spec

from ansible_content_capture.finder import (
    find_all_files,
    label_yml_file,
    get_role_info_from_path,
    get_project_info_for_file,
)
import ansible_content_capture.logger as logger


variable_block_re = re.compile(r"{{[^}]+}}")

magic_vars = []
vars_file = os.getenv("VARS_FILE", os.path.join(os.path.dirname(__file__), "ansible_variables.txt"))
with open(vars_file, "r") as f:
    magic_vars = f.read().splitlines()


bool_values_true = frozenset(("y", "yes", "on", "1", "true", "t", 1, 1.0, True))
bool_values_false = frozenset(("n", "no", "off", "0", "false", "f", 0, 0.0, False))
bool_values = bool_values_true.union(bool_values_false)


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


def get_dir_size(path=""):
    total = 0
    with os.scandir(path) as it:
        for entry in it:
            if entry.is_file(follow_symlinks=False):
                total += entry.stat().st_size
            elif entry.is_dir(follow_symlinks=False):
                total += get_dir_size(entry.path)
    return total


def get_yml_list(root_dir: str):
    found_files = find_all_files(root_dir)
    all_files = []
    for filepath in found_files:
        ext = os.path.splitext(filepath)[1]
        # YAML file
        if ext and ext.lower() in [".yml", ".yaml"]:
            yml_path = filepath
            label, role_info, project_info, name_count, error = get_yml_label(yml_path, root_dir)
            if not role_info:
                role_info = {}
            if not project_info:
                project_info = {}
            if role_info:
                if role_info["path"] and not role_info["path"].startswith(root_dir):
                    role_info["path"] = os.path.join(root_dir, role_info["path"])
                role_info["is_external_dependency"] = True if "." in role_info["name"] else False
            in_role = True if role_info else False
            in_project = True if project_info else False
            all_files.append(
                {
                    "filepath": yml_path,
                    "path_from_root": yml_path.replace(root_dir, "").lstrip("/"),
                    "label": label,
                    "ext": ext,
                    "is_yml": True,
                    "role_info": role_info,
                    "project_info": project_info,
                    "in_role": in_role,
                    "in_project": in_project,
                    "name_count": name_count,
                    "error": error,
                }
            )
        else:
            # non YAML file
            all_files.append(
                {
                    "filepath": filepath,
                    "path_from_root": filepath.replace(root_dir, "").lstrip("/"),
                    "label": "others",
                    "ext": ext,
                    "is_yml": False,
                    "role_info": None,
                    "project_info": None,
                    "in_role": False,
                    "in_project": False,
                    "name_count": -1,
                    "error": None,
                }
            )
    return all_files


def get_yml_label(file_path, root_path):
    if root_path and root_path[-1] == "/":
        root_path = root_path[:-1]

    relative_path = file_path.replace(root_path, "")
    if relative_path[-1] == "/":
        relative_path = relative_path[:-1]

    label, name_count, error = label_yml_file(yml_path=file_path)
    role_name, role_path = get_role_info_from_path(file_path)
    role_info = None
    if role_name and role_path:
        relative_role_path = role_path.replace(root_path, "")
        if relative_role_path and relative_role_path[0] == "/":
            relative_role_path = relative_role_path[1:]
        role_info = {"name": role_name, "path": role_path, "relative_path": relative_role_path}

    project_name, project_path = get_project_info_for_file(file_path, root_path)
    project_info = None
    if project_name and project_path:
        project_info = {"name": project_name, "path": project_path}

    # print(f"[{label}] {relative_path} {role_info}")
    if error:
        logger.debug(f"failed to get yml label:\n {error}")
        label = "error"
    return label, role_info, project_info, name_count, error


def create_scan_list(file_inventory):
    role_file_list = {}
    project_file_list = {}
    independent_file_list = []
    non_yaml_file_list = []
    for file_data in file_inventory:
        filepath = file_data["filepath"]
        path_from_root = file_data["path_from_root"]
        ext = file_data["ext"]
        is_yml = file_data["is_yml"]
        label = file_data["label"]
        role_info = file_data["role_info"]
        in_role = file_data["in_role"]
        project_info = file_data["project_info"]
        in_project = file_data["in_project"]
        name_count = file_data["name_count"]
        error = file_data["error"]
        if is_yml:
            if project_info:
                p_name = project_info.get("name", "")
                p_path = project_info.get("path", "")
                if p_name not in project_file_list:
                    project_file_list[p_name] = {"path": p_path, "files": []}
                project_file_list[p_name]["files"].append(
                    {
                        "filepath": filepath,
                        "path_from_root": path_from_root,
                        "ext": ext,
                        "is_yml": is_yml,
                        "label": label,
                        "project_info": project_info,
                        "role_info": role_info,
                        "in_project": in_project,
                        "in_role": in_role,
                        "name_count": name_count,
                        "error": error,
                    }
                )
            elif role_info:
                r_name = role_info.get("name", "")
                r_path = role_info.get("path", "")
                if role_info.get("is_external_dependency", False):
                    continue
                if r_name not in role_file_list:
                    role_file_list[r_name] = {"path": r_path, "files": []}
                role_file_list[r_name]["files"].append(
                    {
                        "filepath": filepath,
                        "path_from_root": path_from_root,
                        "ext": ext,
                        "is_yml": is_yml,
                        "label": label,
                        "project_info": project_info,
                        "role_info": role_info,
                        "in_project": in_project,
                        "in_role": in_role,
                        "name_count": name_count,
                        "error": error,
                    }
                )
            else:
                independent_file_list.append(
                    {
                        "filepath": filepath,
                        "path_from_root": path_from_root,
                        "ext": ext,
                        "is_yml": is_yml,
                        "label": label,
                        "project_info": project_info,
                        "role_info": role_info,
                        "in_project": in_project,
                        "in_role": in_role,
                        "name_count": name_count,
                        "error": error,
                    }
                )
        else:
            non_yaml_file_list.append(
                {
                    "filepath": filepath,
                    "path_from_root": path_from_root,
                    "ext": ext,
                    "is_yml": is_yml,
                    "label": label,
                    "project_info": project_info,
                    "role_info": role_info,
                    "in_project": in_project,
                    "in_role": in_role,
                    "name_count": name_count,
                    "error": error,
                }
            )
    return project_file_list, role_file_list, independent_file_list, non_yaml_file_list


# NOTE: currently we keep just files that are obviously for vars with a certain path
#       and vars files that are explicitly used in some tasks; other types of files will be skipped
def is_skip_file_obj(obj, tasks=[], plays=[]):
    if not obj or getattr(obj, "type", "") != "file":
        return True

    fpath = getattr(obj, "defined_in") or getattr(obj, "filepath")
    if not fpath:
        return True

    vars_file_patterns = [
        "vars/main.yml",
        "vars/main.yaml",
        "defaults/main.yml",
        "defaults/main.yaml",
    ]
    # check if the filepath is one of role vars files
    for p in vars_file_patterns:
        if p in fpath:
            return False

    # check if the filepath is likely called from known tasks
    for t in tasks:
        module = getattr(t, "module")
        short_module = module.split(".")[-1]
        if short_module != "include_vars":
            continue
        mo = getattr(t, "module_options")

        vars_file_ref_list = []
        loop_info = getattr(t, "loop")
        if loop_info and isinstance(loop_info, dict):
            for loop_var in loop_info:
                loop_items = loop_info[loop_var]
                if isinstance(loop_items, list):
                    for v in loop_items:
                        if isinstance(v, str):
                            vars_file_ref_list.append(v)
                        elif isinstance(v, dict):
                            # `with_first_found` case
                            if "files" in v:
                                vars_file_ref_list.extend(v["files"])
        else:
            vars_file_ref = ""
            if isinstance(mo, str):
                vars_file_ref = mo
            elif isinstance(mo, dict):
                vars_file_ref = mo.get("file", "")
            if vars_file_ref:
                vars_file_ref_list.append(vars_file_ref)
        if not vars_file_ref_list:
            continue

        for vars_file_ref in vars_file_ref_list:
            basename = vars_file_ref.split("/")[-1]
            if basename in fpath:
                return False

    for p in plays:
        vars_files = getattr(p, "vars_files")
        # sometimes `vars_files` contains a loop variable with multiple items
        # then make them flat list
        flat_vars_files = []
        for vars_file in vars_files:
            if isinstance(vars_file, list):
                flat_vars_files.extend(vars_file)
            else:
                flat_vars_files.append(vars_file)

        for vars_file in flat_vars_files:
            basename = vars_file.split("/")[-1]
            if basename in fpath:
                return False

    return True


def flatten_dict_list(d, parent_key="", sep="."):
    items = {}
    if d is None:
        return items
    if isinstance(d, list):
        for i, v in enumerate(d):
            items[i] = v
        return items
    elif isinstance(d, dict):
        for key, value in d.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else key
            if isinstance(value, dict):
                items.update(flatten_dict_list(value, new_key, sep=sep))
            elif isinstance(value, list):
                for v in value:
                    list_new_key = f"{new_key}[{value.index(v)}]"
                    if isinstance(v, dict):
                        items.update(flatten_dict_list(v, list_new_key, sep=sep))
                    else:
                        items[list_new_key] = v
            else:
                items[new_key] = value
    else:
        items["value"] = d
        return items
    return items


def flatten_dict(d, parent_key="", sep="."):
    items = {}
    if isinstance(d, str):
        items["value"] = d
        return items
    if isinstance(d, list):
        for i, v in enumerate(d):
            items[i] = v
        return items
    for key, value in d.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key
        if isinstance(value, dict):
            # add current key and value
            items[key] = value
            # handle child dict
            items.update(flatten_dict(value, new_key, sep=sep))
        else:
            items[new_key] = value
    return items


# return var names
def extract_var_parts(options: dict | str):
    vars_in_option = {}
    if isinstance(options, str):
        if "{{" in options:
            vars = extract_variable_names(options)
            for v in vars:
                vars_in_option[v["name"]] = v
    elif isinstance(options, dict):
        for _, ov in options.items():
            if not isinstance(ov, str):
                continue
            if "{{" in ov:
                vars = extract_variable_names(ov)
                for v in vars:
                    vars_in_option[v["name"]] = v
    return vars_in_option


def extract_variable_names(txt):
    if not variable_block_re.search(txt):
        return []
    found_var_blocks = variable_block_re.findall(txt)
    blocks = []
    for b in found_var_blocks:
        if "lookup(" in b.replace(" ", ""):
            continue
        parts = b.split("|")
        var_name = ""
        default_var_name = ""
        for i, p in enumerate(parts):
            if i == 0:
                var_name = p.replace("{{", "").replace("}}", "")
                if " if " in var_name and " else " in var_name:
                    # this block is not just a variable, but an expression
                    # we need to split this with a space to get its elements
                    skip_elements = ["if", "else", "+", "is", "defined"]
                    sub_parts = var_name.split(" ")
                    for sp in sub_parts:
                        if not sp:
                            continue
                        if sp and sp in skip_elements:
                            continue
                        if sp and sp[0] in ['"', "'"]:
                            continue
                        var_name = sp
                        break
                var_name = var_name.replace(" ", "")
                if "lookup(" in var_name and "first_found" in var_name:
                    var_name = var_name.split(",")[-1].replace(")", "")
                if var_name and var_name[0] == "(":
                    var_name = var_name.split(")")[0].replace("(", "")
                if "+" in var_name:
                    sub_parts = var_name.split("+")
                    for sp in sub_parts:
                        if not sp:
                            continue
                        if sp and sp[0] in ['"', "'"]:
                            continue
                        var_name = sp
                        break
                if "[" in var_name and "." not in var_name:
                    # extract dict/list name
                    dict_pattern = r'(\w+)\[(\'|").*(\'|")\]'
                    match = re.search(dict_pattern, var_name)
                    if match:
                        matched_str = match.group(1)
                        var_name = matched_str.split("[")[0]
                    list_pattern = r"(\w+)\[\-?\d+\]"
                    match = re.search(list_pattern, var_name)
                    if match:
                        matched_str = match.group(1)
                        var_name = matched_str.split("[")[0]
            else:
                if "default(" in p and ")" in p:
                    default_var = p.replace("}}", "").replace("default(", "").replace(")", "").replace(" ", "")
                    if not default_var.startswith('"') and not default_var.startswith("'") and not re.compile(r"[0-9].*").match(default_var):
                        default_var_name = default_var
        tmp_b = {
            "original": b,
        }
        if var_name == "":
            continue
        tmp_b["name"] = var_name
        if default_var_name != "":
            tmp_b["default"] = default_var_name
        blocks.append(tmp_b)
    return blocks


# return used vars in when option
def check_when_option(options):
    used_vars = {}
    if "when" not in options and "failed_when" not in options:
        return used_vars
    when_value = options.get("when", "")
    failed_when_value = options.get("failed_when", "")
    all_values = []
    if isinstance(when_value, list):
        all_values.extend(when_value)

    elif isinstance(when_value, dict):
        for v in when_value.values():
            all_values.append(v)
    else:
        all_values.append(when_value)

    _used_vars = extract_when_option_var_name(all_values)
    used_vars |= _used_vars

    all_values = []
    if isinstance(failed_when_value, list):
        all_values.extend(failed_when_value)
    elif isinstance(failed_when_value, dict):
        for v in failed_when_value.values():
            all_values.append(v)
    else:
        all_values.append(failed_when_value)
        # all_values = re.split('[ |]', f"{failed_when_value}")
    _used_vars = extract_when_option_var_name(all_values, is_failed_when=True)
    used_vars |= _used_vars
    return used_vars


def extract_when_option_var_name(option_parts, is_failed_when=False):
    option_parts = _split_values(option_parts)
    used_vars = {}
    ignore_words = ["defined", "undefined", "is", "not", "and", "or", "|", "in", "none", "+", "vars"]
    boolean_vars = ["True", "true", "t", "yes", "y", "on", "False", "false", "f", "no", "n", "off"]
    data_type_words = ["bool", "float", "int", "length", "string"]
    for p in option_parts:
        if "match(" in p or "default(" in p:
            continue
        p = p.replace(")", "").replace("(", "").replace("{", "").replace("}", "")
        if not p:
            continue
        if "=" in p or "<" in p or ">" in p:
            continue
        if p in ignore_words:
            continue
        if p in boolean_vars:
            continue
        if p in data_type_words:
            continue
        if p.startswith('"') or p.startswith("'"):
            continue
        if p.startswith("[") or p.startswith("]"):
            continue
        if p.startswith("item"):
            continue
        if "[" in p:
            # extract var part from dict format like "hostvars[inventory_hostname]"
            all_parts = re.split(r"[\[]", f"{p}")
            if "[" not in all_parts[0]:
                p = all_parts[0]
        p = p.replace('"', "")
        if is_num(p):
            continue
        if check_if_magic_vars(p):
            continue
        if is_failed_when:
            used_vars[p] = {"original": p, "name": p, "in_failed_when": True}
        else:
            used_vars[p] = {"original": p, "name": p}
    return used_vars


def check_if_magic_vars(used_var):
    if "." in used_var:
        used_var = used_var.split(".")[0]
    if used_var in magic_vars:
        return True
    if used_var.startswith("ansible_"):
        return True
    if used_var == "default(omit)" or used_var == "default(false)":
        return True
    return False


def _split_values(all_values):
    all_parts = []
    for val in all_values:
        # identify string enclosed in (") or (') to support the following case
        # when: result.failed or 'Server API protected' not in result.content
        double_quoted_strings = re.findall(r'"(.*?)"', f"{val}")
        single_quoted_strings = re.findall(r"'(.*?)'", f"{val}")
        for quoted_str in double_quoted_strings:
            if quoted_str != "" and quoted_str != " ":
                val = val.replace(quoted_str, " ")
        for quoted_str in single_quoted_strings:
            if quoted_str != "" and quoted_str != " ":
                val = val.replace(quoted_str, " ")
        all_parts.extend(re.split("[ |]", f"{val}"))
    return all_parts


def is_num(s):
    try:
        float(s)
    except ValueError:
        return False
    else:
        return True


# return the list of parent obj key
def traverse_and_get_parents(node_key, call_tree, parent_nodes):
    sibling = []
    for parent, child in call_tree:
        # sibling
        key_parts = child.key.rsplit("#", 1)
        p1 = key_parts[0]
        p2 = key_parts[-1]
        n_key_parts = node_key.rsplit("#", 1)
        np1 = n_key_parts[0]
        np2 = n_key_parts[-1]
        if "task:" in p2 and "task:" in np2:
            p2_num = int(p2.replace("task:[", "").replace("]", ""))
            np2_num = int(np2.replace("task:[", "").replace("]", ""))
            if p1 == np1 and p2_num < np2_num:
                sibling.insert(0, child.key)
    for parent, child in call_tree:
        # parent
        if child.key == node_key:
            parent_nodes.extend(sibling)
            parent_nodes.append(parent.key)
            traverse_and_get_parents(parent.key, call_tree, parent_nodes)
            break
    # parent_nodes.reverse()
    return parent_nodes


def parse_bool(value: any):
    value_str = None
    use_value_str = False
    if isinstance(value, bool):
        return value
    elif isinstance(value, str):
        value_str = value
        use_value_str = True
    elif isinstance(value, bytes):
        surrogateescape_enabled = False
        try:
            codecs.lookup_error("surrogateescape")
            surrogateescape_enabled = True
        except Exception:
            pass
        errors = "surrogateescape" if surrogateescape_enabled else "strict"
        value_str = value.decode("utf-8", errors)
        use_value_str = True

    if use_value_str and isinstance(value_str, str):
        value_str = value_str.lower().strip()

    target_value = value_str if use_value_str else value

    if target_value in bool_values_true:
        return True
    elif target_value in bool_values_false:
        return False
    else:
        raise TypeError(f'failed to parse the value "{value}" as a boolean.')
