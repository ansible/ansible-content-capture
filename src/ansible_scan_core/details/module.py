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

from ansible_scan_core.models import (
    TaskCall,
    ExecutableType,
)


def set_module_details(task: TaskCall):
    suggested_fqcns = []
    suggested_dependency = []
    resolved_fqcn = ""
    wrong_module_name = ""
    not_exist = False
    correct_fqcn = ""
    need_correction = False

    # normal task
    if task.spec.executable_type == ExecutableType.MODULE_TYPE:

        resolved_fqcn = task.spec.resolved_name
        suggested_fqcns = [cand[0] for cand in task.spec.possible_candidates]
        suggested_dependency = [cand[1] for cand in task.spec.possible_candidates]

        if not task.spec.resolved_name:
            for suggestion in suggested_fqcns:
                if suggestion != task.spec.module and not suggestion.endswith(f".{task.spec.module}"):
                    wrong_module_name = task.spec.module
                    break
            if not task.spec.possible_candidates:
                not_exist = True
                wrong_module_name = task.spec.module

        if task.spec.resolved_name:
            correct_fqcn = task.spec.resolved_name
        elif suggested_fqcns:
            correct_fqcn = suggested_fqcns[0]

        if correct_fqcn != task.spec.module or not_exist:
            need_correction = True

    # include_role, import_role
    elif task.spec.executable_type == ExecutableType.ROLE_TYPE:
        if "ansible.builtin." not in task.spec.module:
            resolved_fqcn = "ansible.builtin." + task.spec.module
            correct_fqcn = resolved_fqcn
            need_correction = True

    # include_tasks, import_tasks
    elif task.spec.executable_type == ExecutableType.TASKFILE_TYPE:
        if "ansible.builtin." not in task.spec.module:
            resolved_fqcn = "ansible.builtin." + task.spec.module
            correct_fqcn = resolved_fqcn
            need_correction = True

    module_examples = ""
    if task.module:
        module_examples = task.module.examples

    task.spec.set_annotation("module.suggested_fqcn", suggested_fqcns)
    task.spec.set_annotation("module.suggested_dependency", suggested_dependency)
    task.spec.set_annotation("module.resolved_fqcn", resolved_fqcn)
    task.spec.set_annotation("module.wrong_module_name", wrong_module_name)
    task.spec.set_annotation("module.not_exist", not_exist)
    task.spec.set_annotation("module.correct_fqcn", correct_fqcn)
    task.spec.set_annotation("module.need_correction", need_correction)

    task.spec.set_annotation("module.examples", module_examples)

    return None
