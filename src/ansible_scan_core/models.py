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

from dataclasses import dataclass, field
from typing import List
from tabulate import tabulate
from ruamel.yaml.scalarstring import DoubleQuotedScalarString

from copy import deepcopy
import json
import jsonpickle
import Levenshtein
import ansible_scan_core.yaml as ayaml
from ansible.module_utils.parsing.convert_bool import boolean
from .keyutil import (
    set_collection_key,
    set_module_key,
    set_play_key,
    set_playbook_key,
    set_repository_key,
    set_role_key,
    set_task_key,
    set_taskfile_key,
    set_file_key,
    set_call_object_key,
)
from .utils import (
    recursive_copy_dict,
)


class PlaybookFormatError(Exception):
    pass


class TaskFormatError(Exception):
    pass


class JSONSerializable(object):
    def dump(self):
        return self.to_json()

    def to_json(self):
        return jsonpickle.encode(self, make_refs=False)

    @classmethod
    def from_json(cls, json_str):
        instance = cls()
        loaded = jsonpickle.decode(json_str)
        instance.__dict__.update(loaded.__dict__)
        return instance


@dataclass
class VariablePrecedence(object):
    name: str = ""
    order: int = -1

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def __eq__(self, __o: object) -> bool:
        return self.order == __o.order

    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)

    def __lt__(self, __o: object):
        return self.order < __o.order

    def __le__(self, __o: object):
        return self.__lt__(__o) or self.__eq__(__o)

    def __gt__(self, __o: object):
        return not self.__le__(__o)

    def __ge__(self, __o: object):
        return not self.__lt__(__o)



class VariableType(object):
    # When resolving variables, sometimes find unknown variables (e.g. undefined variable)
    # so we consider it as one type of variable
    Unknown = VariablePrecedence("unknown", -100)
    # Variable Precedence
    # https://docs.ansible.com/ansible/latest/playbook_guide
    #     /playbooks_variables.html#understanding-variable-precedence
    CommandLineValues = VariablePrecedence("command_line_values", 1)
    RoleDefaults = VariablePrecedence("role_defaults", 2)
    InventoryFileOrScriptGroupVars = VariablePrecedence("inventory_file_or_script_group_vars", 3)
    InventoryGroupVarsAll = VariablePrecedence("inventory_group_vars_all", 4)
    PlaybookGroupVarsAll = VariablePrecedence("playbook_group_vars_all", 5)
    InventoryGroupVarsAny = VariablePrecedence("inventory_group_vars_any", 6)
    PlaybookGroupVarsAny = VariablePrecedence("playbook_group_vars_any", 7)
    InventoryFileOrScriptHostVars = VariablePrecedence("inventory_file_or_script_host_vars", 8)
    InventoryHostVarsAny = VariablePrecedence("inventory_host_vars_any", 9)
    PlaybookHostVarsAny = VariablePrecedence("playbook_host_vars_any", 10)
    HostFacts = VariablePrecedence("host_facts", 11)
    PlayVars = VariablePrecedence("play_vars", 12)
    PlayVarsPrompt = VariablePrecedence("play_vars_prompt", 13)
    PlayVarsFiles = VariablePrecedence("play_vars_files", 14)
    RoleVars = VariablePrecedence("role_vars", 15)
    BlockVars = VariablePrecedence("block_vars", 16)
    TaskVars = VariablePrecedence("task_vars", 17)
    IncludeVars = VariablePrecedence("include_vars", 18)
    # we deal with set_facts and registered_vars separately
    # because the expression in a fact will be evaluated everytime it is used
    SetFacts = VariablePrecedence("set_facts", 19)
    RegisteredVars = VariablePrecedence("registered_vars", 20)
    RoleParams = VariablePrecedence("role_params", 21)
    IncludeParams = VariablePrecedence("include_params", 22)
    ExtraVars = VariablePrecedence("extra_vars", 23)
    # vars defined in `loop` cannot be overridden by the vars above
    # so we put this as a highest precedence var type
    LoopVars = VariablePrecedence("loop_vars", 24)


immutable_var_types = [VariableType.LoopVars]


@dataclass
class Variable(object):
    name: str = ""
    value: any = None
    type: VariableType = None
    elements: list = field(default_factory=list)
    setter: any = None
    used_in: any = None

    @property
    def is_mutable(self):
        return self.type not in immutable_var_types


@dataclass
class VariableDict(object):
    _dict: dict = field(default_factory=dict)

    @staticmethod
    def print_table(data: dict):
        d = VariableDict(_dict=data)
        table = []
        type_labels = []
        found_type_label_names = []
        for v_list in d._dict.values():
            for v in v_list:
                if v.type.name in found_type_label_names:
                    continue
                type_labels.append(v.type)
                found_type_label_names.append(v.type.name)
        type_labels = sorted(type_labels, key=lambda x: x.order, reverse=True)

        for v_name in d._dict:
            v_list = d._dict[v_name]
            row = {"NAME": v_name}
            for t in type_labels:
                value = "-"
                for v in v_list:
                    if v.type != t:
                        continue
                    value = v.value
                    if isinstance(value, str) and value == "":
                        value = '""'
                type_label = t.name.upper()
                row[type_label] = value
            table.append(row)
        return tabulate(table, headers="keys")

class ArgumentsType(object):
    SIMPLE = "simple"
    LIST = "list"
    DICT = "dict"


@dataclass
class Arguments(object):
    type: ArgumentsType = ""
    raw: any = None
    vars: List[Variable] = field(default_factory=list)
    resolved: bool = False
    templated: any = None
    is_mutable: bool = False

    def get(self, key: str = ""):
        sub_raw = None
        sub_templated = None
        if key == "":
            sub_raw = self.raw
            sub_templated = self.templated
        else:
            if isinstance(self.raw, dict):
                sub_raw = self.raw.get(key, None)
                if self.templated:
                    sub_templated = self.templated[0].get(key, None)
            else:
                sub_raw = self.raw
                sub_templated = self.templated
        if not sub_raw:
            return None

        _vars = []
        sub_type = ArgumentsType.SIMPLE
        if isinstance(sub_raw, str):
            for v in self.vars:
                if v.name in sub_raw:
                    _vars.append(v)
        elif isinstance(sub_raw, list):
            sub_type = ArgumentsType.LIST
        elif isinstance(sub_raw, dict):
            sub_type = ArgumentsType.DICT
        is_mutable = False
        for v in _vars:
            if v.is_mutable:
                is_mutable = True
                break

        return Arguments(
            type=sub_type,
            raw=sub_raw,
            vars=_vars,
            resolved=self.resolved,
            templated=sub_templated,
            is_mutable=is_mutable,
        )


@dataclass
class Annotation(JSONSerializable):
    key: str = ""
    value: any = None

    # TODO: avoid Annotation variants and remove `type`
    type: str = ""


@dataclass
class VariableAnnotation(Annotation):
    type: str = "variable_annotation"
    option_value: Arguments = field(default_factory=Arguments)


class Resolvable(object):
    def resolve(self, resolver):
        if not hasattr(resolver, "apply"):
            raise ValueError("this resolver does not have apply() method")
        if not callable(resolver.apply):
            raise ValueError("resolver.apply is not callable")

        # apply resolver for this instance
        resolver.apply(self)

        # call resolve() for children recursively
        targets = self.resolver_targets
        if targets is None:
            return
        for t in targets:
            if isinstance(t, str):
                continue
            t.resolve(resolver)

        # apply resolver again here
        # because some attributes was not set at first
        resolver.apply(self)
        return

    @property
    def resolver_targets(self):
        raise NotImplementedError


class LoadType:
    PROJECT = "project"
    COLLECTION = "collection"
    ROLE = "role"
    PLAYBOOK = "playbook"
    TASKFILE = "taskfile"
    UNKNOWN = "unknown"


@dataclass
class Load(JSONSerializable):
    target_name: str = ""
    target_type: str = ""
    path: str = ""
    loader_version: str = ""
    playbook_yaml: str = ""
    playbook_only: bool = False
    taskfile_yaml: str = ""
    taskfile_only: bool = False
    base_dir: str = ""
    include_test_contents: bool = False
    yaml_label_list: list = field(default_factory=list)
    timestamp: str = ""

    # the following variables are list of paths; not object
    roles: list = field(default_factory=list)
    playbooks: list = field(default_factory=list)
    taskfiles: list = field(default_factory=list)
    modules: list = field(default_factory=list)
    files: list = field(default_factory=list)


@dataclass
class Annotatable(JSONSerializable):
    # annotations are used for storing generic data
    annotations: List[Annotation] = field(default_factory=list)

    def get_annotation_by_type(self, type_str=""):
        matched = [an for an in self.annotations if an.type == type_str]
        return matched

    def get_annotation_by_type_and_attr(self, type_str="", key="", val=None):
        matched = [an for an in self.annotations if hasattr(an, "type") and an.type == type_str and getattr(an, key, None) == val]
        return matched

    def set_annotation(self, key: str, value: any):
        end_to_set = False
        for an in self.annotations:
            if not hasattr(an, "key"):
                continue
            if getattr(an, "key") == key:
                setattr(an, "value", value)
                end_to_set = True
                break
        if not end_to_set:
            self.annotations.append(Annotation(key=key, value=value))
        return

    def get_annotation(self, key: str, __default: any = None):
        value = __default
        for an in self.annotations:
            if not hasattr(an, "key"):
                continue
            if getattr(an, "key") == key:
                value = getattr(an, "value", __default)
                break
        return value


@dataclass
class Object(Annotatable):
    type: str = ""
    key: str = ""


@dataclass
class ObjectList(JSONSerializable):
    items: list = field(default_factory=list)
    _dict: dict = field(default_factory=dict)

    def dump(self, fpath=""):
        return self.to_json(fpath=fpath)

    def to_json(self, fpath=""):
        lines = [jsonpickle.encode(obj, make_refs=False) for obj in self.items]
        json_str = "\n".join(lines)
        if fpath != "":
            open(fpath, "w").write(json_str)
        return json_str

    def to_one_line_json(self):
        return jsonpickle.encode(self.items, make_refs=False)

    @classmethod
    def from_json(cls, json_str="", fpath=""):
        instance = cls()
        if fpath != "":
            json_str = open(fpath, "r").read()
        lines = json_str.splitlines()
        items = [jsonpickle.decode(obj_str) for obj_str in lines]
        instance.items = items
        instance._update_dict()
        return instance

    def add(self, obj, update_dict=True):
        self.items.append(obj)
        if update_dict:
            self._add_dict_item(obj)
        return

    def merge(self, obj_list):
        if not isinstance(obj_list, ObjectList):
            raise ValueError("obj_list must be an instance of ObjectList, but got {}".format(type(obj_list).__name__))
        self.items.extend(obj_list.items)
        self._update_dict()
        return

    def find_by_attr(self, key, val):
        found = [obj for obj in self.items if obj.__dict__.get(key, None) == val]
        return found

    def find_by_type(self, type):
        return [obj for obj in self.items if hasattr(obj, "type") and obj.type == type]

    def find_by_key(self, key):
        return self._dict.get(key, None)

    def contains(self, key="", obj=None):
        if obj is not None:
            key = obj.key
        return self.find_by_key(key) is not None

    def update_dict(self):
        self._update_dict()

    def _update_dict(self):
        for obj in self.items:
            self._dict[obj.key] = obj
        return

    def _add_dict_item(self, obj):
        self._dict[obj.key] = obj

    @property
    def resolver_targets(self):
        return self.items


@dataclass
class CallObject(Annotatable):
    type: str = ""
    key: str = ""
    called_from: str = ""
    spec: Object = field(default_factory=Object)
    depth: int = -1
    node_id: str = ""

    @classmethod
    def from_spec(cls, spec, caller, index):
        instance = cls()
        instance.spec = spec
        caller_key = "None"
        depth = 0
        node_id = "0"
        if caller:
            instance.called_from = caller.key
            caller_key = caller.key
            depth = caller.depth + 1
            index_str = "0"
            if index >= 0:
                index_str = str(index)
            node_id = caller.node_id + "." + index_str
        instance.depth = depth
        instance.node_id = node_id
        instance.key = set_call_object_key(cls.__name__, spec.key, caller_key)
        return instance


class RunTargetType:
    Playbook = "playbookcall"
    Play = "playcall"
    Role = "rolecall"
    TaskFile = "taskfilecall"
    Task = "taskcall"


@dataclass
class RunTarget(object):
    type: str = ""

    def file_info(self):
        file = self.spec.defined_in
        lines = None
        return file, lines


@dataclass
class RunTargetList(object):
    items: List[RunTarget] = field(default_factory=list)

    _i: int = 0

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        return self

    def __next__(self):
        if self._i == len(self.items):
            self._i = 0
            raise StopIteration()
        item = self.items[self._i]
        self._i += 1
        return item

    def __getitem__(self, i):
        return self.items[i]


@dataclass
class File(object):
    type: str = "file"
    name: str = ""
    key: str = ""
    local_key: str = ""
    role: str = ""
    collection: str = ""

    body: str = ""
    data: any = None
    encrypted: bool = False
    error: str = ""
    label: str = ""
    defined_in: str = ""

    annotations: dict = field(default_factory=dict)

    def set_key(self):
        set_file_key(self)

    def children_to_key(self):
        return self

    @property
    def resolver_targets(self):
        return None


@dataclass
class ModuleArgument(object):
    name: str = ""
    type: str = None
    elements: str = None
    default: any = None
    required: bool = False
    description: str = ""
    choices: list = field(default_factory=list)
    aliases: list = field(default_factory=list)

    def available_keys(self):
        keys = [self.name]
        if self.aliases:
            keys.extend(self.aliases)
        return keys


@dataclass
class Module(Object, Resolvable):
    type: str = "module"
    name: str = ""
    fqcn: str = ""
    key: str = ""
    local_key: str = ""
    collection: str = ""
    role: str = ""
    documentation: str = ""
    examples: str = ""
    arguments: list = field(default_factory=list)
    defined_in: str = ""
    builtin: bool = False
    used_in: list = field(default_factory=list)  # resolved later

    annotations: dict = field(default_factory=dict)

    def set_key(self):
        set_module_key(self)

    def children_to_key(self):
        return self

    @property
    def resolver_targets(self):
        return None


@dataclass
class ModuleCall(CallObject, Resolvable):
    type: str = "modulecall"


@dataclass
class Collection(Object, Resolvable):
    type: str = "collection"
    name: str = ""
    path: str = ""
    key: str = ""
    local_key: str = ""
    metadata: dict = field(default_factory=dict)
    meta_runtime: dict = field(default_factory=dict)
    files: dict = field(default_factory=dict)
    playbooks: list = field(default_factory=list)
    taskfiles: list = field(default_factory=list)
    roles: list = field(default_factory=list)
    modules: list = field(default_factory=list)
    dependency: dict = field(default_factory=dict)
    requirements: dict = field(default_factory=dict)

    annotations: dict = field(default_factory=dict)

    variables: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)

    def set_key(self):
        set_collection_key(self)

    def children_to_key(self):
        module_keys = [m.key if isinstance(m, Module) else m for m in self.modules]
        self.modules = sorted(module_keys)

        playbook_keys = [p.key if isinstance(p, Playbook) else p for p in self.playbooks]
        self.playbooks = sorted(playbook_keys)

        role_keys = [r.key if isinstance(r, Role) else r for r in self.roles]
        self.roles = sorted(role_keys)

        taskfile_keys = [tf.key if isinstance(tf, TaskFile) else tf for tf in self.taskfiles]
        self.taskfiles = sorted(taskfile_keys)
        return self

    @property
    def resolver_targets(self):
        return self.playbooks + self.taskfiles + self.roles + self.modules


@dataclass
class CollectionCall(CallObject, Resolvable):
    type: str = "collectioncall"


@dataclass
class TaskCallsInTree(JSONSerializable):
    root_key: str = ""
    taskcalls: list = field(default_factory=list)


def _convert_to_bool(a: any):
    if isinstance(a, bool):
        return bool(a)
    if isinstance(a, str):
        if a == "true" or a == "True" or a == "yes":
            return True
        else:
            return False
    return None


class ExecutableType:
    MODULE_TYPE = "Module"
    ROLE_TYPE = "Role"
    TASKFILE_TYPE = "TaskFile"


@dataclass
class BecomeInfo(object):
    enabled: bool = False
    become: str = ""
    user: str = ""
    method: str = ""
    flags: str = ""

    @staticmethod
    def from_options(options: dict):
        if "become" in options:
            become = options.get("become", "")
            enabled = False
            try:
                enabled = boolean(become)
            except Exception:
                pass
            user = options.get("become_user", "")
            method = options.get("become_method", "")
            flags = options.get("become_flags", "")
            return BecomeInfo(enabled=enabled, user=user, method=method, flags=flags)
        return None


@dataclass
class Task(Object, Resolvable):
    type: str = "task"
    name: str = ""
    module: str = ""
    index: int = -1
    play_index: int = -1
    defined_in: str = ""
    key: str = ""
    local_key: str = ""
    role: str = ""
    collection: str = ""
    become: BecomeInfo = None
    variables: dict = field(default_factory=dict)
    module_defaults: dict = field(default_factory=dict)
    registered_variables: dict = field(default_factory=dict)
    set_facts: dict = field(default_factory=dict)
    loop: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    module_options: dict = field(default_factory=dict)
    executable: str = ""
    executable_type: str = ""
    collections_in_play: list = field(default_factory=list)

    yaml_lines: str = ""
    line_num_in_file: list = field(default_factory=list)  # [begin, end]

    # FQCN for Module and Role. Or a file path for TaskFile.  resolved later
    resolved_name: str = ""
    # candidates of resovled_name
    possible_candidates: list = field(default_factory=list)

    # embed these data when module/role/taskfile are resolved
    module_info: dict = field(default_factory=dict)
    include_info: dict = field(default_factory=dict)

    def set_yaml_lines(self, fullpath="", yaml_lines="", task_name="", module_name="", module_options=None, task_options=None, previous_task_line=-1):
        if not task_name and not module_options:
            return

        lines = []
        if yaml_lines:
            lines = yaml_lines.splitlines()
        else:
            lines = open(fullpath, "r").read().splitlines()

        # search candidates that match either of the following conditions
        #   - task name is included in the line
        #   - if module name is included,
        #       - if module option is string, it is included
        #       - if module option is dict, at least one key is included
        candidate_line_nums = []
        for i, line in enumerate(lines):

            # skip lines until `previous_task_line` if provided
            if previous_task_line > 0:
                if i <= previous_task_line - 1:
                    continue

            if task_name:
                if task_name in line:
                    candidate_line_nums.append(i)
            elif "{}:".format(module_name) in line:
                if isinstance(module_options, str):
                    if module_options in line:
                        candidate_line_nums.append(i)
                elif isinstance(module_options, dict):
                    option_matched = False
                    for key in module_options:
                        if i + 1 < len(lines) and "{}:".format(key) in lines[i + 1]:
                            option_matched = True
                            break
                    if option_matched:
                        candidate_line_nums.append(i)
        if not candidate_line_nums:
            return

        # get task yaml_lines for each candidate
        candidate_blocks = []
        for candidate_line_num in candidate_line_nums:
            _yaml_lines, _line_num_in_file = self._find_task_block(lines, candidate_line_num)
            if _yaml_lines and _line_num_in_file:
                candidate_blocks.append((_yaml_lines, _line_num_in_file))

        if not candidate_blocks:
            return

        reconstructed_yaml = ""
        best_yaml_lines = ""
        best_line_num_in_file = []
        sorted_candidates = []
        if len(candidate_blocks) == 1:
            best_yaml_lines = candidate_blocks[0][0]
            best_line_num_in_file = candidate_blocks[0][1]
        else:
            # reconstruct yaml from the task data to calculate similarity (edit distance) later
            reconstructed_data = [{}]
            if task_name:
                reconstructed_data[0]["name"] = task_name
            reconstructed_data[0][module_name] = module_options
            if isinstance(task_options, dict):
                for key, val in task_options.items():
                    if key not in reconstructed_data[0]:
                        reconstructed_data[0][key] = val

            try:
                reconstructed_yaml = ayaml.dump(reconstructed_data)
            except Exception:
                pass

            # find best match by edit distance
            if reconstructed_yaml:

                def remove_comment_lines(s):
                    lines = s.splitlines()
                    updated = []
                    for line in lines:
                        if line.strip().startswith("#"):
                            continue
                        updated.append(line)
                    return "\n".join(updated)

                def calc_dist(s1, s2):
                    us1 = remove_comment_lines(s1)
                    us2 = remove_comment_lines(s2)
                    dist = Levenshtein.distance(us1, us2)
                    return dist

                r = reconstructed_yaml
                sorted_candidates = sorted(candidate_blocks, key=lambda x: calc_dist(r, x[0]))
                best_yaml_lines = sorted_candidates[0][0]
                best_line_num_in_file = sorted_candidates[0][1]
            else:
                # give up here if yaml reconstruction failed
                # use the first candidate
                best_yaml_lines = candidate_blocks[0][0]
                best_line_num_in_file = candidate_blocks[0][1]

        self.yaml_lines = best_yaml_lines
        self.line_num_in_file = best_line_num_in_file
        return

    def _find_task_block(self, yaml_lines: list, start_line_num: int):
        if not yaml_lines:
            return None, None

        if start_line_num < 0:
            return None, None

        lines = yaml_lines
        found_line = lines[start_line_num]
        is_top_of_block = found_line.replace(" ", "").startswith("-")
        begin_line_num = start_line_num
        indent_of_block = -1
        if is_top_of_block:
            indent_of_block = len(found_line.split("-")[0])
        else:
            found = False
            found_line = ""
            _indent_of_block = -1
            parts = found_line.split(" ")
            for i, p in enumerate(parts):
                if p != "":
                    break
                _indent_of_block = i + 1
            for i in range(len(lines)):
                index = begin_line_num
                _line = lines[index]
                is_top_of_block = _line.replace(" ", "").startswith("-")
                if is_top_of_block:
                    _indent = len(_line.split("-")[0])
                    if _indent < _indent_of_block:
                        found = True
                        found_line = _line
                        break
                begin_line_num -= 1
                if begin_line_num < 0:
                    break
            if not found:
                return None, None
            indent_of_block = len(found_line.split("-")[0])
        index = begin_line_num + 1
        end_found = False
        end_line_num = -1
        for i in range(len(lines)):
            if index >= len(lines):
                break
            _line = lines[index]
            is_top_of_block = _line.replace(" ", "").startswith("-")
            if is_top_of_block:
                _indent = len(_line.split("-")[0])
                if _indent <= indent_of_block:
                    end_found = True
                    end_line_num = index - 1
                    break
            index += 1
            if index >= len(lines):
                end_found = True
                end_line_num = index
                break
        if not end_found:
            return None, None
        if begin_line_num < 0 or end_line_num > len(lines) or begin_line_num > end_line_num:
            return None, None

        yaml_lines = "\n".join(lines[begin_line_num : end_line_num + 1])
        line_num_in_file = [begin_line_num + 1, end_line_num + 1]
        return yaml_lines, line_num_in_file

    # this keeps original contents like comments, indentation
    # and quotes for string as much as possible
    def yaml(self, original_module="", use_yaml_lines=True):
        task_data_wrapper = None
        task_data = None
        if use_yaml_lines:
            try:
                task_data_wrapper = ayaml.load(self.yaml_lines)
                task_data = task_data_wrapper[0]
            except Exception:
                pass

            if not task_data:
                return self.yaml_lines
        else:
            task_data_wrapper = []
            task_data = {}

        # task name
        if self.name:
            task_data["name"] = self.name
        elif "name" in task_data:
            task_data.pop("name")

        # module name
        if original_module:
            mo = deepcopy(task_data[original_module])
            task_data[self.module] = mo
        elif self.module and self.module not in task_data:
            task_data[self.module] = self.module_options

        # module options
        if isinstance(self.module_options, dict):
            current_mo = task_data[self.module]
            # if the module options was an old style inline parameter in YAML,
            # we can ignore them here because it is parsed as self.module_options
            if not isinstance(current_mo, dict):
                current_mo = {}
            old_keys = list(current_mo.keys())
            new_keys = list(self.module_options.keys())
            for old_key in old_keys:
                if old_key not in new_keys:
                    current_mo.pop(old_key)
            recursive_copy_dict(self.module_options, current_mo)
            task_data[self.module] = current_mo

        # task options
        if isinstance(self.options, dict):
            current_to = task_data
            old_keys = list(current_to.keys())
            new_keys = list(self.options.keys())
            for old_key in old_keys:
                if old_key in ["name", self.module]:
                    continue
                if old_key not in new_keys:
                    current_to.pop(old_key)
            options_without_name = {k: v for k, v in self.options.items() if k != "name"}
            recursive_copy_dict(options_without_name, current_to)
        if len(task_data_wrapper) == 0:
            task_data_wrapper.append(current_to)
        else:
            task_data_wrapper[0] = current_to
        new_yaml = ayaml.dump(task_data_wrapper)
        return new_yaml

    # this makes a yaml from task contents such as spec.module,
    # spec.options, spec.module_options in a fixed format
    # NOTE: this will lose comments and indentations in the original YAML
    def formatted_yaml(self):
        task_data = {}
        if self.name:
            task_data["name"] = self.name
        if self.module:
            task_data[self.module] = self.module_options
        for key, val in self.options.items():
            if key == "name":
                continue
            task_data[key] = val
        task_data = self.str2double_quoted_scalar(task_data)
        data = [task_data]
        return ayaml.dump(data)

    def str2double_quoted_scalar(self, v):
        if isinstance(v, dict):
            for key, val in v.items():
                new_val = self.str2double_quoted_scalar(val)
                v[key] = new_val
        elif isinstance(v, list):
            for i, val in enumerate(v):
                new_val = self.str2double_quoted_scalar(val)
                v[i] = new_val
        elif isinstance(v, str):
            v = DoubleQuotedScalarString(v)
        else:
            pass
        return v

    def set_key(self, parent_key="", parent_local_key=""):
        set_task_key(self, parent_key, parent_local_key)

    def children_to_key(self):
        return self

    @property
    def defined_vars(self):
        d_vars = self.variables
        d_vars.update(self.registered_variables)
        d_vars.update(self.set_facts)
        return d_vars

    @property
    def tags(self):
        return self.options.get("tags", None)

    @property
    def when(self):
        return self.options.get("when", None)

    @property
    def action(self):
        return self.executable

    @property
    def resolved_action(self):
        return self.resolved_name

    @property
    def line_number(self):
        return self.line_num_in_file

    @property
    def id(self):
        return json.dumps(
            {
                "path": self.defined_in,
                "index": self.index,
                "play_index": self.play_index,
            }
        )

    @property
    def resolver_targets(self):
        return None


@dataclass
class MutableContent(object):
    _yaml: str = ""
    _task_spec: Task = None

    @staticmethod
    def from_task_spec(task_spec):
        mc = MutableContent(
            _yaml=task_spec.yaml_lines,
            _task_spec=deepcopy(task_spec),
        )
        return mc

    def set_task_name(self, task_name: str):
        # if `name` is None or empty string, Task.yaml() won't output the field
        self._task_spec.name = task_name
        self._yaml = self._task_spec.yaml()
        self._task_spec.yaml_lines = self._yaml
        return self

    def get_task_name(self):
        return self._task_spec.name

    def omit_task_name(self):
        # if `name` is None or empty string, Task.yaml() won't output the field
        self._task_spec.name = None
        self._yaml = self._task_spec.yaml()
        self._task_spec.yaml_lines = self._yaml
        return self

    def set_module_name(self, module_name):
        original_module = deepcopy(self._task_spec.module)
        self._task_spec.module = module_name
        self._yaml = self._task_spec.yaml(original_module=original_module)
        self._task_spec.yaml_lines = self._yaml
        return self

    def replace_key(self, old_key: str, new_key: str):
        if old_key in self._task_spec.options:
            value = self._task_spec.options[old_key]
            self._task_spec.options.pop(old_key)
            self._task_spec.options[new_key] = value
        self._yaml = self._task_spec.yaml()
        self._task_spec.yaml_lines = self._yaml
        return self

    def replace_value(self, old_value: str, new_value: str):
        original_new_value = deepcopy(new_value)
        need_restore = False
        keys_to_be_restored = []
        if isinstance(new_value, str):
            new_value = DoubleQuotedScalarString(new_value)
            need_restore = True
        for k, v in self._task_spec.options.items():
            if type(v).__name__ != type(old_value).__name__:
                continue
            if v != old_value:
                continue
            self._task_spec.options[k] = new_value
            keys_to_be_restored.append(k)
        self._yaml = self._task_spec.yaml()
        self._task_spec.yaml_lines = self._yaml
        if need_restore:
            for k, v in self._task_spec.options.items():
                if k in keys_to_be_restored:
                    self._task_spec.options[k] = original_new_value
        return self

    def remove_key(self, key):
        if key in self._task_spec.options:
            self._task_spec.options.pop(key)
        self._yaml = self._task_spec.yaml()
        self._task_spec.yaml_lines = self._yaml
        return self

    def set_new_module_arg_key(self, key, value):
        original_value = deepcopy(value)
        need_restore = False
        if isinstance(value, str):
            value = DoubleQuotedScalarString(value)
            need_restore = True
        self._task_spec.module_options[key] = value
        self._yaml = self._task_spec.yaml()
        self._task_spec.yaml_lines = self._yaml
        if need_restore:
            self._task_spec.module_options[key] = original_value
        return self

    def remove_module_arg_key(self, key):
        if key in self._task_spec.module_options:
            self._task_spec.module_options.pop(key)
        self._yaml = self._task_spec.yaml()
        self._task_spec.yaml_lines = self._yaml
        return self

    def replace_module_arg_key(self, old_key: str, new_key: str):
        if old_key in self._task_spec.module_options:
            value = self._task_spec.module_options[old_key]
            self._task_spec.module_options.pop(old_key)
            self._task_spec.module_options[new_key] = value
        self._yaml = self._task_spec.yaml()
        self._task_spec.yaml_lines = self._yaml
        return self

    def replace_module_arg_value(self, key: str = "", old_value: any = None, new_value: any = None):
        original_new_value = deepcopy(new_value)
        need_restore = False
        keys_to_be_restored = []
        if isinstance(new_value, str):
            new_value = DoubleQuotedScalarString(new_value)
            need_restore = True
        for k in self._task_spec.module_options:
            # if `key` is specified, skip other keys
            if key and k != key:
                continue
            value = self._task_spec.module_options[k]
            if type(value).__name__ == type(old_value).__name__ and value == old_value:
                self._task_spec.module_options[k] = new_value
                keys_to_be_restored.append(k)
        self._yaml = self._task_spec.yaml()
        self._task_spec.yaml_lines = self._yaml
        if need_restore:
            for k in self._task_spec.module_options:
                if k in keys_to_be_restored:
                    self._task_spec.module_options[k] = original_new_value
        return self

    def replace_with_dict(self, new_dict: dict):
        # import this here to avoid circular import
        from .model_loader import load_task

        yaml_lines = ayaml.dump([new_dict])
        new_task = load_task(
            path=self._task_spec.defined_in,
            index=self._task_spec.index,
            task_block_dict=new_dict,
            role_name=self._task_spec.role,
            collection_name=self._task_spec.collection,
            collections_in_play=self._task_spec.collections_in_play,
            play_index=self._task_spec.play_index,
            yaml_lines=yaml_lines,
        )
        self._yaml = yaml_lines
        self._task_spec = new_task
        return self

    def replace_module_arg_with_dict(self, new_dict: dict):
        self._task_spec.module_options = new_dict
        self._yaml = self._task_spec.yaml()
        return self

    # this keeps original contents like comments, indentation
    # and quotes for string as much as possible
    def yaml(self):
        return self._yaml

    # this makes a yaml from task contents such as spec.module,
    # spec.options, spec.module_options in a fixed format
    # NOTE: this will lose comments and indentations in the original YAML
    def formatted_yaml(self):
        return self._task_spec.formatted_yaml()


@dataclass
class TaskCall(CallObject, RunTarget):
    type: str = "taskcall"
    args: Arguments = field(default_factory=Arguments)
    variable_set: dict = field(default_factory=dict)
    variable_use: dict = field(default_factory=dict)
    become: BecomeInfo = None
    module_defaults: dict = field(default_factory=dict)

    module: Module = None
    content: MutableContent = None

    def file_info(self):
        file = self.spec.defined_in
        lines = "?"
        if len(self.spec.line_number) == 2:
            l_num = self.spec.line_number
            lines = f"L{l_num[0]}-{l_num[1]}"
        return file, lines

    @property
    def resolved_name(self):
        return self.spec.resolved_name

    @property
    def resolved_action(self):
        return self.resolved_name

    @property
    def action_type(self):
        return self.spec.executable_type


@dataclass
class TaskFile(Object, Resolvable):
    type: str = "taskfile"
    name: str = ""
    defined_in: str = ""
    key: str = ""
    local_key: str = ""
    tasks: list = field(default_factory=list)
    # role name of this task file
    # this might be empty because a task file can be defined out of roles
    role: str = ""
    collection: str = ""

    yaml_lines: str = ""

    used_in: list = field(default_factory=list)  # resolved later

    annotations: dict = field(default_factory=dict)

    variables: dict = field(default_factory=dict)
    module_defaults: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)

    task_loading: dict = field(default_factory=dict)

    def set_key(self):
        set_taskfile_key(self)

    def children_to_key(self):
        task_keys = [t.key if isinstance(t, Task) else t for t in self.tasks]
        self.tasks = task_keys
        return self

    @property
    def resolver_targets(self):
        return self.tasks


@dataclass
class TaskFileCall(CallObject, RunTarget):
    type: str = "taskfilecall"


@dataclass
class Role(Object, Resolvable):
    type: str = "role"
    name: str = ""
    defined_in: str = ""
    key: str = ""
    local_key: str = ""
    fqcn: str = ""
    metadata: dict = field(default_factory=dict)
    collection: str = ""
    playbooks: list = field(default_factory=list)
    # 1 role can have multiple task yamls
    taskfiles: list = field(default_factory=list)
    handlers: list = field(default_factory=list)
    # roles/xxxx/library/zzzz.py can be called as module zzzz
    modules: list = field(default_factory=list)
    dependency: dict = field(default_factory=dict)
    requirements: dict = field(default_factory=dict)

    source: str = ""  # collection/scm repo/galaxy

    annotations: dict = field(default_factory=dict)

    default_variables: dict = field(default_factory=dict)
    variables: dict = field(default_factory=dict)
    # key: loop_var (default "item"), value: list/dict of item value
    loop: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)

    def set_key(self):
        set_role_key(self)

    def children_to_key(self):
        module_keys = [m.key if isinstance(m, Module) else m for m in self.modules]
        self.modules = sorted(module_keys)

        playbook_keys = [p.key if isinstance(p, Playbook) else p for p in self.playbooks]
        self.playbooks = sorted(playbook_keys)

        taskfile_keys = [tf.key if isinstance(tf, TaskFile) else tf for tf in self.taskfiles]
        self.taskfiles = sorted(taskfile_keys)
        return self

    @property
    def resolver_targets(self):
        return self.taskfiles + self.modules


@dataclass
class RoleCall(CallObject, RunTarget):
    type: str = "rolecall"


@dataclass
class RoleInPlay(Object, Resolvable):
    type: str = "roleinplay"
    name: str = ""
    options: dict = field(default_factory=dict)
    defined_in: str = ""
    role_index: int = -1
    play_index: int = -1

    role: str = ""
    collection: str = ""

    resolved_name: str = ""  # resolved later
    # candidates of resovled_name
    possible_candidates: list = field(default_factory=list)

    annotations: dict = field(default_factory=dict)
    collections_in_play: list = field(default_factory=list)

    # embed this data when role is resolved
    role_info: dict = field(default_factory=dict)

    @property
    def resolver_targets(self):
        return None


@dataclass
class RoleInPlayCall(CallObject):
    type: str = "roleinplaycall"


@dataclass
class Play(Object, Resolvable):
    type: str = "play"
    name: str = ""
    defined_in: str = ""
    index: int = -1
    key: str = ""
    local_key: str = ""

    role: str = ""
    collection: str = ""
    import_module: str = ""
    import_playbook: str = ""
    pre_tasks: list = field(default_factory=list)
    tasks: list = field(default_factory=list)
    post_tasks: list = field(default_factory=list)
    handlers: list = field(default_factory=list)
    # not actual Role, but RoleInPlay defined in this playbook
    roles: list = field(default_factory=list)
    module_defaults: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)
    collections_in_play: list = field(default_factory=list)
    become: BecomeInfo = None
    variables: dict = field(default_factory=dict)
    vars_files: list = field(default_factory=list)

    task_loading: dict = field(default_factory=dict)

    def set_key(self, parent_key="", parent_local_key=""):
        set_play_key(self, parent_key, parent_local_key)

    def children_to_key(self):
        pre_task_keys = [t.key if isinstance(t, Task) else t for t in self.pre_tasks]
        self.pre_tasks = pre_task_keys

        task_keys = [t.key if isinstance(t, Task) else t for t in self.tasks]
        self.tasks = task_keys

        post_task_keys = [t.key if isinstance(t, Task) else t for t in self.post_tasks]
        self.post_tasks = post_task_keys

        handler_task_keys = [t.key if isinstance(t, Task) else t for t in self.handlers]
        self.handlers = handler_task_keys
        return self

    @property
    def id(self):
        return json.dumps({"path": self.defined_in, "index": self.index})

    @property
    def resolver_targets(self):
        return self.pre_tasks + self.tasks + self.roles


@dataclass
class PlayCall(CallObject, RunTarget):
    type: str = "playcall"


@dataclass
class Playbook(Object, Resolvable):
    type: str = "playbook"
    name: str = ""
    defined_in: str = ""
    key: str = ""
    local_key: str = ""

    yaml_lines: str = ""

    role: str = ""
    collection: str = ""

    plays: list = field(default_factory=list)

    used_in: list = field(default_factory=list)  # resolved later

    annotations: dict = field(default_factory=dict)

    variables: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)

    def set_key(self):
        set_playbook_key(self)

    def children_to_key(self):
        play_keys = [play.key if isinstance(play, Play) else play for play in self.plays]
        self.plays = play_keys
        return self

    @property
    def resolver_targets(self):
        if "plays" in self.__dict__:
            return self.plays
        else:
            return self.roles + self.tasks


@dataclass
class PlaybookCall(CallObject, RunTarget):
    type: str = "playbookcall"


class InventoryType:
    GROUP_VARS_TYPE = "group_vars"
    HOST_VARS_TYPE = "host_vars"
    UNKNOWN_TYPE = ""


@dataclass
class Inventory(JSONSerializable):
    type: str = "inventory"
    name: str = ""
    defined_in: str = ""
    inventory_type: str = ""
    group_name: str = ""
    host_name: str = ""
    variables: dict = field(default_factory=dict)


@dataclass
class Repository(Object, Resolvable):
    type: str = "repository"
    name: str = ""
    path: str = ""
    key: str = ""
    local_key: str = ""

    # if set, this repository is a collection repository
    my_collection_name: str = ""

    playbooks: list = field(default_factory=list)
    roles: list = field(default_factory=list)

    # for playbook scan
    target_playbook_path: str = ""

    # for taskfile scan
    target_taskfile_path: str = ""

    requirements: dict = field(default_factory=dict)

    installed_collections_path: str = ""
    installed_collections: list = field(default_factory=list)

    installed_roles_path: str = ""
    installed_roles: list = field(default_factory=list)
    modules: list = field(default_factory=list)
    taskfiles: list = field(default_factory=list)

    inventories: list = field(default_factory=list)

    files: list = field(default_factory=list)

    version: str = ""

    annotations: dict = field(default_factory=dict)

    def set_key(self):
        set_repository_key(self)

    def children_to_key(self):
        module_keys = [m.key if isinstance(m, Module) else m for m in self.modules]
        self.modules = sorted(module_keys)

        playbook_keys = [p.key if isinstance(p, Playbook) else p for p in self.playbooks]
        self.playbooks = sorted(playbook_keys)

        taskfile_keys = [tf.key if isinstance(tf, TaskFile) else tf for tf in self.taskfiles]
        self.taskfiles = sorted(taskfile_keys)

        role_keys = [r.key if isinstance(r, Role) else r for r in self.roles]
        self.roles = sorted(role_keys)
        return self

    @property
    def resolver_targets(self):
        return self.playbooks + self.roles + self.modules + self.installed_roles + self.installed_collections


@dataclass
class RepositoryCall(CallObject):
    type: str = "repositorycall"


def call_obj_from_spec(spec: Object, caller: CallObject, index: int = 0):
    if isinstance(spec, Repository):
        return RepositoryCall.from_spec(spec, caller, index)
    elif isinstance(spec, Playbook):
        return PlaybookCall.from_spec(spec, caller, index)
    elif isinstance(spec, Play):
        return PlayCall.from_spec(spec, caller, index)
    elif isinstance(spec, RoleInPlay):
        return RoleInPlayCall.from_spec(spec, caller, index)
    elif isinstance(spec, Role):
        return RoleCall.from_spec(spec, caller, index)
    elif isinstance(spec, TaskFile):
        return TaskFileCall.from_spec(spec, caller, index)
    elif isinstance(spec, Task):
        taskcall = TaskCall.from_spec(spec, caller, index)
        taskcall.content = MutableContent.from_task_spec(task_spec=spec)
        return taskcall
    elif isinstance(spec, Module):
        return ModuleCall.from_spec(spec, caller, index)
    return None


# inherit Repository just for convenience
# this is not a Repository but one or multiple Role / Collection
@dataclass
class GalaxyArtifact(Repository):
    type: str = ""  # Role or Collection

    # make it easier to search a module
    module_dict: dict = field(default_factory=dict)
    # make it easier to search a task
    task_dict: dict = field(default_factory=dict)
    # make it easier to search a taskfile
    taskfile_dict: dict = field(default_factory=dict)
    # make it easier to search a role
    role_dict: dict = field(default_factory=dict)
    # make it easier to search a playbook
    playbook_dict: dict = field(default_factory=dict)
    # make it easier to search a collection
    collection_dict: dict = field(default_factory=dict)


@dataclass
class ModuleMetadata(object):
    fqcn: str = ""
    # arguments: list = field(default_factory=list)
    type: str = ""
    name: str = ""
    version: str = ""
    hash: str = ""
    deprecated: bool = False

    @staticmethod
    def from_module(m: Module, metadata: dict):
        mm = ModuleMetadata()
        for key in mm.__dict__:
            if hasattr(m, key):
                val = getattr(m, key, None)
                setattr(mm, key, val)

        mm.type = metadata.get("type", "")
        mm.name = metadata.get("name", "")
        mm.version = metadata.get("version", "")
        mm.hash = metadata.get("hash", "")
        return mm

    @staticmethod
    def from_routing(dst: str, metadata: dict):
        mm = ModuleMetadata()
        mm.fqcn = dst
        mm.type = metadata.get("type", "")
        mm.name = metadata.get("name", "")
        mm.version = metadata.get("version", "")
        mm.hash = metadata.get("hash", "")
        mm.deprecated = True
        return mm

    @staticmethod
    def from_dict(d: dict):
        mm = ModuleMetadata()
        mm.fqcn = d.get("fqcn", "")
        mm.type = d.get("type", "")
        mm.name = d.get("name", "")
        mm.version = d.get("version", "")
        mm.hash = d.get("hash", "")
        return mm

    def __eq__(self, mm):
        if not isinstance(mm, ModuleMetadata):
            return False
        return self.fqcn == mm.fqcn and self.name == mm.name and self.type == mm.type and self.version == mm.version and self.hash == mm.hash


@dataclass
class RoleMetadata(object):
    fqcn: str = ""
    type: str = ""
    name: str = ""
    version: str = ""
    hash: str = ""

    @staticmethod
    def from_role(r: Role, metadata: dict):
        rm = RoleMetadata()
        for key in rm.__dict__:
            if hasattr(r, key):
                val = getattr(r, key, None)
                setattr(rm, key, val)

        rm.type = metadata.get("type", "")
        rm.name = metadata.get("name", "")
        rm.version = metadata.get("version", "")
        rm.hash = metadata.get("hash", "")
        return rm

    @staticmethod
    def from_dict(d: dict):
        rm = RoleMetadata()
        rm.fqcn = d.get("fqcn", "")
        rm.type = d.get("type", "")
        rm.name = d.get("name", "")
        rm.version = d.get("version", "")
        rm.hash = d.get("hash", "")
        return rm

    def __eq__(self, rm):
        if not isinstance(rm, ModuleMetadata):
            return False
        return self.fqcn == rm.fqcn and self.name == rm.name and self.type == rm.type and self.version == rm.version and self.hash == rm.hash


@dataclass
class TaskFileMetadata(object):
    key: str = ""
    type: str = ""
    name: str = ""
    version: str = ""
    hash: str = ""

    @staticmethod
    def from_taskfile(tf: TaskFile, metadata: dict):
        tfm = TaskFileMetadata()
        for key in tfm.__dict__:
            if hasattr(tf, key):
                val = getattr(tf, key, None)
                setattr(tfm, key, val)

        tfm.type = metadata.get("type", "")
        tfm.name = metadata.get("name", "")
        tfm.version = metadata.get("version", "")
        tfm.hash = metadata.get("hash", "")
        return tfm

    @staticmethod
    def from_dict(d: dict):
        tfm = RoleMetadata()
        tfm.key = d.get("key", "")
        tfm.type = d.get("type", "")
        tfm.name = d.get("name", "")
        tfm.version = d.get("version", "")
        tfm.hash = d.get("hash", "")
        return tfm

    def __eq__(self, tfm):
        if not isinstance(tfm, TaskFileMetadata):
            return False
        return self.key == tfm.key and self.name == tfm.name and self.type == tfm.type and self.version == tfm.version and self.hash == tfm.hash


@dataclass
class ActionGroupMetadata(object):
    group_name: str = ""
    group_modules: list = field(default_factory=list)
    type: str = ""
    name: str = ""
    version: str = ""
    hash: str = ""

    @staticmethod
    def from_action_group(group_name: str, group_modules: list, metadata: dict):
        if not group_name:
            return None

        if not group_modules:
            return None

        agm = ActionGroupMetadata()
        agm.group_name = group_name
        agm.group_modules = group_modules
        agm.type = metadata.get("type", "")
        agm.name = metadata.get("name", "")
        agm.version = metadata.get("version", "")
        agm.hash = metadata.get("hash", "")
        return agm

    @staticmethod
    def from_dict(d: dict):
        agm = ActionGroupMetadata()
        agm.group_name = d.get("group_name", "")
        agm.group_modules = d.get("group_modules", "")
        agm.type = d.get("type", "")
        agm.name = d.get("name", "")
        agm.version = d.get("version", "")
        agm.hash = d.get("hash", "")
        return agm

    def __eq__(self, agm):
        if not isinstance(agm, ActionGroupMetadata):
            return False
        return (
            self.group_name == agm.group_name
            and self.name == agm.name
            and self.type == agm.type
            and self.version == agm.version
            and self.hash == agm.hash
        )
