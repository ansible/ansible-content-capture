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

from ansible_content_capture.models import (
    TaskCall,
    ArgumentsType,
    ExecutableType,
    VariableType,
)


def is_loop_var(value, task):
    # `item` and alternative loop variable (if any) should not be replaced to avoid breaking loop
    skip_variables = ["item"]
    if task.spec.loop and isinstance(task.spec.loop, dict):
        skip_variables.extend(list(task.spec.loop.keys()))

    _v = value.replace(" ", "")

    for var in skip_variables:
        for _prefix in ["}}", "|", "."]:
            pattern = "{{" + var + _prefix
            if pattern in _v:
                return True
    return False


def is_debug(module_fqcn):
    return module_fqcn == "ansible.builtin.debug"


def set_argument_value_details(task: TaskCall):
    if task.spec.executable_type == ExecutableType.MODULE_TYPE and task.module and task.module.arguments:
        wrong_values = []
        undefined_values = []
        unknown_type_values = []

        registered_vars = []
        for v_name in task.variable_set:
            v = task.variable_set[v_name]
            if v and v[-1].type == VariableType.RegisteredVars:
                registered_vars.append(v_name)

        module_fqcn = task.module.fqcn

        if task.args.type == ArgumentsType.DICT:
            for key in task.args.raw:
                raw_value = task.args.raw[key]
                resolved_value = None
                if len(task.args.templated) >= 1:
                    resolved_value = task.args.templated[0][key]
                spec = None
                for arg_spec in task.module.arguments:
                    if key == arg_spec.name or (arg_spec.aliases and key in arg_spec.aliases):
                        spec = arg_spec
                        break
                if not spec:
                    continue

                d = {"key": key}
                wrong_val = False
                unknown_type_val = False
                if spec.type and not is_debug(module_fqcn):
                    actual_type = ""
                    # if the raw_value is not a variable
                    if not isinstance(raw_value, str) or "{{" not in raw_value:
                        actual_type = type(raw_value).__name__
                    else:
                        # otherwise, check the resolved value
                        # if the variable could not be resovled successfully
                        if isinstance(resolved_value, str) and "{{" in resolved_value:
                            pass
                        elif is_loop_var(raw_value, task):
                            # if the variable is loop var, use the element type as actual type
                            resolved_element = None
                            if resolved_value:
                                resolved_element = resolved_value[0]
                            if resolved_element:
                                actual_type = type(resolved_element).__name__
                        else:
                            # otherwise, use the resolved value type as actual type
                            actual_type = type(resolved_value).__name__

                    if actual_type:
                        type_wrong = False
                        if spec.type != "any" and actual_type != spec.type:
                            type_wrong = True

                        elements_type = spec.elements
                        if spec.type == "list" and not spec.elements:
                            elements_type = "any"

                        elements_type_wrong = False
                        no_elements = False
                        if elements_type:
                            if elements_type != "any" and actual_type != elements_type:
                                elements_type_wrong = True
                        else:
                            no_elements = True
                        if type_wrong and (elements_type_wrong or no_elements):
                            d["expected_type"] = spec.type
                            d["actual_type"] = actual_type
                            d["actual_value"] = raw_value
                            wrong_val = True
                    else:
                        d["expected_type"] = spec.type
                        d["unknown_type_value"] = resolved_value
                        unknown_type_val = True

                if wrong_val:
                    wrong_values.append(d)

                if unknown_type_val:
                    unknown_type_values.append(d)

                sub_args = task.args.get(key)
                if sub_args:
                    undefined_vars = []
                    for v in sub_args.vars:
                        first_v_name = v.name.split(".")[0]
                        # skip registered vars
                        if first_v_name in registered_vars:
                            continue

                        if v and v.type == VariableType.Unknown:
                            undefined_vars.append(v.name)

                    if undefined_vars:
                        undefined_values.append({"key": key, "value": raw_value, "undefined_variables": undefined_vars})

        task.spec.set_annotation("module.wrong_arg_values", wrong_values)
        task.spec.set_annotation("module.undefined_values", undefined_values)
        task.spec.set_annotation("module.unknown_type_values", unknown_type_values)

    # TODO: find duplicate keys

    return None
