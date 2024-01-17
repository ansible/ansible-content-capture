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
from ansible_scan_core.scanner import AnsibleScanner


scanner = AnsibleScanner()


def test_evaluate_yaml():
    target_yaml = """
---
- hosts: localhost
  vars:
    name: "John"
  tasks:
    - name: Greetings
      debug:
        msg: "Hello, {{ name }}!  {{ additional_comment }}"
        abc: def
"""
    scandata = scanner.evaluate(type="playbook", raw_yaml=target_yaml)

    # check result data structure
    assert(scandata)
    assert(scandata.root_definitions)
    definitions = scandata.root_definitions["definitions"]
    assert(definitions)
    tasks = definitions["tasks"]
    assert(tasks)
    assert(len(tasks) == 1)
    task = tasks[0]
    assert(task)

    # check module fqcn
    fqcn = task.get_annotation("module.correct_fqcn")
    assert(fqcn)
    assert(fqcn == "ansible.builtin.debug")

    # check wrong arg key
    wrong_keys = task.get_annotation("module.wrong_arg_keys")
    assert(wrong_keys)
    assert(len(wrong_keys) == 1)
    wrong_key = wrong_keys[0]
    assert(wrong_key == "abc")

    # check undefined variable
    undefined_vars = task.get_annotation("variable.undefined_vars")
    assert(undefined_vars)
    assert(len(undefined_vars)==1)
    undefined_var = undefined_vars[0]
    assert(undefined_var == "additional_comment")


def test_evaluate_collection():
    target_path = os.path.join(os.path.dirname(__file__), "testdata/sample_collection/ansible_collections/kubernetes/core")
    scandata = scanner.evaluate(
        type="collection",
        path=target_path,
        collection_name="kubernetes.core",
        include_test_contents=True,
    )
    # check result data structure
    assert(scandata)
    assert(scandata.root_definitions)
    definitions = scandata.root_definitions["definitions"]
    assert(definitions)
    modules = definitions["modules"]
    assert(modules)
    assert(len(modules) == 23)
    taskfiles = definitions["taskfiles"]
    assert(taskfiles)
    taskfile_path_list = [tf.filepath for tf in taskfiles]
    assert("tests/integration/targets/helm/tasks/main.yml" in taskfile_path_list)
    assert("tests/integration/targets/setup_namespace/tasks/main.yml" in taskfile_path_list)


def test_evaluate_role():
    target_path = os.path.join(os.path.dirname(__file__), "testdata/sample_role/geerlingguy.docker")
    scandata = scanner.evaluate(
        type="role",
        path=target_path,
    )
    # check result data structure
    assert(scandata)
    assert(scandata.root_definitions)
    definitions = scandata.root_definitions["definitions"]
    assert(definitions)
    taskfiles = definitions["taskfiles"]
    assert(taskfiles)
    taskfile_path_list = [tf.filepath for tf in taskfiles]
    assert("tasks/setup-Debian.yml" in taskfile_path_list)
    assert("tasks/docker-users.yml" in taskfile_path_list)


def test_scan_yaml():
    target_yaml = """
---
- hosts: localhost
  vars:
    name: "John"
  tasks:
    - name: Greetings
      debug:
        msg: "Hello, {{ name }}!  {{ additional_comment }}"
        abc: def
"""
    scan_result = scanner.run(
        raw_yaml=target_yaml,
    )
    assert(scan_result)
    assert(scan_result.tasks)
    assert(len(scan_result.tasks) == 1)
    task = scan_result.tasks[0]
    assert(task.name == "Greetings")


def test_scan_collection():
    target_path = os.path.join(os.path.dirname(__file__), "testdata/sample_collection/ansible_collections/kubernetes/core")
    scan_result = scanner.run(
        target_dir=target_path,
    )
    # check result data structure
    assert(scan_result)
    assert(scan_result.modules)
    modules = scan_result.modules
    assert(modules)
    assert(len(modules) == 23)
    taskfiles = scan_result.taskfiles
    assert(taskfiles)
    taskfile_path_list = [tf.filepath for tf in taskfiles]
    assert("tests/integration/targets/helm/tasks/main.yml" in taskfile_path_list)
    assert("tests/integration/targets/setup_namespace/tasks/main.yml" in taskfile_path_list)