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
import sys
import json

from ansible_scan_core.scanner import AnsibleScanner


_single_file_scan_path = "__in_memory__"
_root_caller = "None"


def main():
    target_path = sys.argv[1]
    original_path = target_path
    if target_path[0] != "/":
        cwd = os.getcwd()
        target_path = os.path.join(cwd, target_path)

    scanner = AnsibleScanner()

    result = None
    if os.path.isfile(target_path):
        raw_yaml = ""
        with open(target_path, "r") as f:
            raw_yaml = f.read()
        result = scanner.run(raw_yaml=raw_yaml)
    else:
        result = scanner.run(target_dir=target_path)

    call_dict = {}
    obj_dict = {}
    tree_dict = {}
    for tree in result.trees:
        for call in tree.items:
            obj = call.spec
            call_dict[call.key] = obj.key
            parent_key = call_dict.get(call.called_from, "root")

            obj_info = {}
            _type = obj.type
            obj_info["type"] = _type
            filepath = obj.filepath
            if obj.filepath == _single_file_scan_path:
                filepath = original_path
            if filepath:
                obj_info["filepath"] = filepath

            if _type == "role":
                if obj.default_variables:
                    obj_info["default_variables"] = obj.default_variables
                if obj.variables:
                    obj_info["variables"] = obj.variables

            elif _type == "task":
                line_num = f"{obj.line_num_in_file[0]} - {obj.line_num_in_file[1]}"
                obj_info["lines"] = line_num

                obj_info["name"] = obj.name

                obj_info["module"] = obj.module

            elif _type == "module":
                obj_info["fqcn"] = obj.fqcn

            info_str = json.dumps(obj_info)

            parent_str = obj_dict.get(parent_key, "root")

            if parent_str not in tree_dict:
                tree_dict[parent_str] = []
            tree_dict[parent_str].append(info_str)

            obj_dict[obj.key] = info_str

    ptree("root", tree_dict)


def ptree(start, tree, indent_width=2):
    def _ptree(start, parent, tree, grandpa=None, indent=""):
        if parent != start:
            if grandpa is None:  # Ask grandpa kids!
                print(parent, end="")
            else:
                print(parent)
        if parent not in tree:
            return
        for child in tree[parent][:-1]:
            print(indent + "├" + "─" * indent_width, end="")
            _ptree(start, child, tree, parent, indent + "│" + " " * 4)
        child = tree[parent][-1]
        print(indent + "└" + "─" * indent_width, end="")
        _ptree(start, child, tree, parent, indent + " " * 5)  # 4 -> 5

    parent = start
    print(start)
    _ptree(start, parent, tree)


if __name__ == "__main__":
    main()
