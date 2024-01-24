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
import pathlib
import json
import pygit2
import pkg_resources
from .models import LoadType

collection_manifest_json = "MANIFEST.json"
role_meta_main_yml = "meta/main.yml"
role_meta_main_yaml = "meta/main.yaml"


# remove a dir which is a sub directory of another dir in the list
def remove_subdirectories(dir_list):
    sorted_dir_list = sorted(dir_list)
    new_dir_list = []
    for i, dir in enumerate(sorted_dir_list):
        if i >= 1 and dir.startswith(sorted_dir_list[i - 1]):
            continue
        new_dir_list.append(dir)
    return new_dir_list


def trim_suffix(txt, suffix_patterns=[]):
    if isinstance(suffix_patterns, str):
        suffix_patterns = [suffix_patterns]
    if not isinstance(suffix_patterns, list):
        return txt
    for suffix in suffix_patterns:
        if txt.endswith(suffix):
            return txt[: -len(suffix)]
    return txt


def get_scanner_version():
    version = ""
    # try to get version from the installed executable
    try:
        version = pkg_resources.require("ansible-scan-core")[0].version
    except Exception:
        pass
    if version != "":
        return version
    # try to get version from commit ID in source code repository
    try:
        script_dir = pathlib.Path(__file__).parent.resolve()
        repo = pygit2.Repository(script_dir)
        version = repo.head.target
    except Exception:
        pass
    return version


def get_target_name(target_type, target_path):
    target_name = ""
    if target_type == LoadType.PROJECT:
        project_name = os.path.normpath(target_path).split("/")[-1]
        target_name = project_name
    elif target_type == LoadType.COLLECTION:
        meta_file = os.path.join(target_path, collection_manifest_json)
        metadata = {}
        with open(meta_file, "r") as file:
            metadata = json.load(file)
        collection_namespace = metadata.get("collection_info", {}).get("namespace", "")
        collection_name = metadata.get("collection_info", {}).get("name", "")
        target_name = "{}.{}".format(collection_namespace, collection_name)
    elif target_type == LoadType.ROLE:
        # any better approach?
        target_name = target_path.split("/")[-1]
    elif target_type == LoadType.PLAYBOOK:
        target_name = filepath_to_target_name(target_path)
    return target_name


def filepath_to_target_name(filepath):
    return filepath.translate(str.maketrans({" ": "___", "/": "---", ".": "_dot_"}))
