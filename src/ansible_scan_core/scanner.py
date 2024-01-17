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
import time
import sys
import json
import yaml
import tempfile
import jsonpickle
import datetime
import traceback
from dataclasses import dataclass, field

from .models import (
    Object,
    Load,
    LoadType,
    ObjectList,
    TaskCallsInTree,
    InputData,
    ScanResult,
)
from .loader import (
    get_scanner_version,
)
from .parser import Parser
from .model_loader import load_object
from .tree import TreeLoader
from .variable_resolver import resolve_variables
from .dependency_dir_preparator import (
    DependencyDirPreparator,
)
from .details.argument_key import set_argument_key_details
from .details.argument_value import set_argument_value_details
from .details.module import set_module_details
from .details.variable import set_variable_details
from .findings import Findings
from .knowledge_base import KBClient
import ansible_scan_core.logger as logger
from .utils import (
    is_url,
    is_local_path,
    escape_url,
    escape_local_path,
    split_target_playbook_fullpath,
    split_target_taskfile_fullpath,
    equal,
    get_dir_size,
    get_yml_list,
    create_scan_list,
    is_skip_file_obj,
    label_yml_file,
)


default_config_path = os.path.expanduser("~/.ansible_scan/config")
default_data_dir = os.path.join("/tmp", "ansible-scan-data")
default_log_level = "info"
default_logger_key = "ansible-scan"


@dataclass
class Config:
    path: str = ""

    data_dir: str = ""
    logger_key: str = ""
    log_level: str = ""

    _data: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.path:
            self.path = default_config_path
        config_data = {}
        if os.path.exists(self.path):
            with open(self.path, "r") as file:
                try:
                    config_data = yaml.safe_load(file)
                except Exception as e:
                    raise ValueError(f"failed to load the config file: {e}")
        if config_data:
            self._data = config_data

        if not self.data_dir:
            self.data_dir = self._get_single_config("ANSIBLE_SCAN_DATA_DIR", "data_dir", default_data_dir)
        if not self.logger_key:
            self.logger_key = self._get_single_config("ANSIBLE_SCAN_LOGGER_KEY", "logger_key", default_logger_key)
        if not self.log_level:
            self.log_level = self._get_single_config("ANSIBLE_SCAN_LOG_LEVEL", "log_level", default_log_level)

    def _get_single_config(self, env_key: str = "", yaml_key: str = "", __default: any = None, __type=None, separator=""):
        if env_key in os.environ:
            _from_env = os.environ.get(env_key, None)
            if _from_env and __type:
                if __type == "list":
                    _from_env = _from_env.split(separator)
            return _from_env
        elif yaml_key in self._data:
            _from_file = self._data.get(yaml_key, None)
            return _from_file
        else:
            return __default


collection_manifest_json = "MANIFEST.json"
role_meta_main_yml = "meta/main.yml"
role_meta_main_yaml = "meta/main.yaml"


supported_target_types = [
    LoadType.PROJECT,
    LoadType.COLLECTION,
    LoadType.ROLE,
    LoadType.PLAYBOOK,
]

config = Config()

logger.set_logger_channel(config.logger_key)
logger.set_log_level(config.log_level)


@dataclass
class ScanData(object):
    type: str = ""
    name: str = ""
    collection_name: str = ""
    role_name: str = ""
    target_playbook_name: str = None
    playbook_yaml: str = ""
    playbook_only: bool = False
    target_taskfile_name: str = None
    taskfile_yaml: str = ""
    taskfile_only: bool = False

    skip_playbook_format_error: bool = (True,)
    skip_task_format_error: bool = (True,)

    install_log: str = ""
    tmp_install_dir: tempfile.TemporaryDirectory = None

    index: dict = field(default_factory=dict)

    root_definitions: dict = field(default_factory=dict)
    ext_definitions: dict = field(default_factory=dict)

    target_object: Object = field(default_factory=Object)

    trees: list = field(default_factory=list)
    # for inventory object
    additional: ObjectList = field(default_factory=ObjectList)

    taskcalls_in_trees: list = field(default_factory=list)

    data_report: dict = field(default_factory=dict)

    _path_mappings: dict = field(default_factory=dict)

    install_dependencies: bool = False
    use_ansible_path: bool = False

    dependency_dir: str = ""
    base_dir: str = ""
    target_path: str = ""
    loaded_dependency_dirs: list = field(default_factory=list)
    use_src_cache: bool = True

    prm: dict = field(default_factory=dict)

    download_url: str = ""
    version: str = ""
    hash: str = ""

    source_repository: str = ""
    out_dir: str = ""

    include_test_contents: bool = False
    load_all_taskfiles: bool = False
    yaml_label_list: list = field(default_factory=list)

    extra_requirements: list = field(default_factory=list)
    resolve_failures: dict = field(default_factory=dict)

    findings: Findings = None

    # the following are set by Ansible Scanner
    root_dir: str = ""
    persist_dependency_cache: bool = False
    spec_mutations_from_previous_scan: dict = field(default_factory=dict)
    spec_mutations: dict = field(default_factory=dict)
    use_ansible_doc: bool = True
    do_save: bool = False
    silent: bool = False
    _parser: Parser = None

    def __post_init__(self):
        if self.type == LoadType.COLLECTION or self.type == LoadType.ROLE:
            type_root = self.type + "s"
            target_name = self.name
            if is_local_path(target_name):
                target_name = escape_local_path(target_name)
            self._path_mappings = {
                "src": os.path.join(self.root_dir, type_root, "src"),
                "root_definitions": os.path.join(
                    self.root_dir,
                    type_root,
                    "root",
                    "definitions",
                    type_root,
                    target_name,
                ),
                "ext_definitions": {
                    LoadType.ROLE: os.path.join(self.root_dir, "roles", "definitions"),
                    LoadType.COLLECTION: os.path.join(self.root_dir, "collections", "definitions"),
                },
                "index": os.path.join(
                    self.root_dir,
                    type_root,
                    "{}-{}-index-ext.json".format(self.type, target_name),
                ),
                "install_log": os.path.join(
                    self.root_dir,
                    type_root,
                    "{}-{}-install.log".format(self.type, target_name),
                ),
            }

        elif self.type == LoadType.PROJECT or self.type == LoadType.PLAYBOOK or self.type == LoadType.TASKFILE:
            type_root = self.type + "s"
            proj_name = escape_url(self.name)
            if self.type == LoadType.PLAYBOOK:
                if self.playbook_yaml:
                    self.target_playbook_name = self.name
                else:
                    if self.base_dir:
                        basedir = self.base_dir
                        target_playbook_path = self.name.replace(basedir, "")
                        if target_playbook_path[0] == "/":
                            target_playbook_path = target_playbook_path[1:]
                        self.target_playbook_name = target_playbook_path
                    else:
                        _, self.target_playbook_name = split_target_playbook_fullpath(self.name)
            elif self.type == LoadType.TASKFILE:
                if self.taskfile_yaml:
                    self.target_taskfile_name = self.name
                else:
                    if self.base_dir:
                        basedir = self.base_dir
                        target_taskfile_path = self.name.replace(basedir, "")
                        if target_taskfile_path[0] == "/":
                            target_taskfile_path = target_taskfile_path[1:]
                        self.target_taskfile_name = target_taskfile_path
                    else:
                        _, self.target_taskfile_name = split_target_taskfile_fullpath(self.name)
            self._path_mappings = {
                "src": os.path.join(self.root_dir, type_root, proj_name, "src"),
                "root_definitions": os.path.join(
                    self.root_dir,
                    type_root,
                    proj_name,
                    "definitions",
                ),
                "ext_definitions": {
                    LoadType.ROLE: os.path.join(self.root_dir, "roles", "definitions"),
                    LoadType.COLLECTION: os.path.join(self.root_dir, "collections", "definitions"),
                },
                "index": os.path.join(
                    self.root_dir,
                    type_root,
                    proj_name,
                    "index-ext.json",
                ),
                "install_log": os.path.join(
                    self.root_dir,
                    type_root,
                    proj_name,
                    "{}-{}-install.log".format(self.type, proj_name),
                ),
                "dependencies": os.path.join(self.root_dir, type_root, proj_name, "dependencies"),
            }

        else:
            raise ValueError("Unsupported type: {}".format(self.type))

        if self.playbook_yaml:
            self.playbook_only = True
            if not self.name:
                self.name = "__in_memory__"
                self.target_playbook_name = self.name

        if self.taskfile_yaml:
            self.taskfile_only = True
            if not self.name:
                self.name = "__in_memory__"
                self.target_taskfile_name = self.name

    def make_target_path(self, typ, target_name, dep_dir=""):
        target_path = ""

        if dep_dir:
            parts = target_name.split(".")
            if len(parts) == 1:
                parts.append("")
            dep_dir_target_path_candidates = [
                os.path.join(dep_dir, target_name),
                os.path.join(dep_dir, parts[0], parts[1]),
                os.path.join(dep_dir, "ansible_collections", parts[0], parts[1]),
            ]
            for cand_path in dep_dir_target_path_candidates:
                if os.path.exists(cand_path):
                    target_path = cand_path
                    break
        if target_path != "":
            return target_path

        if typ == LoadType.COLLECTION:
            parts = target_name.split(".")
            if is_local_path(target_name):
                target_path = target_name
            else:
                target_path = os.path.join(self.root_dir, typ + "s", "src", "ansible_collections", parts[0], parts[1])
        elif typ == LoadType.ROLE:
            if is_local_path(target_name):
                target_path = target_name
            else:
                target_path = os.path.join(self.root_dir, typ + "s", "src", target_name)
        elif typ == LoadType.PROJECT:
            if is_url(target_name):
                target_path = os.path.join(self.get_src_root(), escape_url(target_name))
            else:
                target_path = target_name
        elif typ == LoadType.PLAYBOOK:
            if is_url(target_name):
                target_path = os.path.join(self.get_src_root(), escape_url(target_name))
            else:
                target_path = target_name
        elif typ == LoadType.TASKFILE:
            if is_url(target_name):
                target_path = os.path.join(self.get_src_root(), escape_url(target_name))
            else:
                target_path = target_name
        return target_path

    def get_src_root(self):
        return self._path_mappings["src"]

    def is_src_installed(self):
        index_location = self._path_mappings["index"]
        return os.path.exists(index_location)

    def _prepare_dependencies(self, root_install=True):
        # Install the target if needed
        target_path = self.make_target_path(self.type, self.name)

        # Dependency Dir Preparator
        ddp = DependencyDirPreparator(
            root_dir=self.root_dir,
            source_repository=self.source_repository,
            target_type=self.type,
            target_name=self.name,
            target_version=self.version,
            target_path=target_path,
            target_dependency_dir=self.dependency_dir,
            target_path_mappings=self._path_mappings,
            do_save=self.do_save,
            silent=self.silent,
            tmp_install_dir=self.tmp_install_dir,
            periodical_cleanup=self.persist_dependency_cache,
        )
        dep_dirs = ddp.prepare_dir(
            root_install=root_install,
            use_ansible_path=self.use_ansible_path,
            is_src_installed=self.is_src_installed(),
            cache_enabled=self.use_src_cache,
            cache_dir=os.path.join(self.root_dir, "archives"),
        )

        self.target_path = target_path
        self.version = ddp.metadata.version
        self.hash = ddp.metadata.hash
        self.download_url = ddp.metadata.download_url
        self.loaded_dependency_dirs = dep_dirs

        return target_path, dep_dirs

    def create_load_file(self, target_type, target_name, target_path):

        loader_version = get_scanner_version()

        if not os.path.exists(target_path) and not self.playbook_yaml and not self.taskfile_yaml:
            raise ValueError("No such file or directory: {}".format(target_path))
        if not self.silent:
            logger.debug(f"target_name: {target_name}")
            logger.debug(f"target_type: {target_type}")
            logger.debug(f"path: {target_path}")
            logger.debug(f"loader_version: {loader_version}")
        ld = Load(
            target_name=target_name,
            target_type=target_type,
            path=target_path,
            loader_version=loader_version,
            playbook_yaml=self.playbook_yaml,
            playbook_only=self.playbook_only,
            taskfile_yaml=self.taskfile_yaml,
            taskfile_only=self.taskfile_only,
            base_dir=self.base_dir,
            include_test_contents=self.include_test_contents,
            yaml_label_list=self.yaml_label_list,
        )
        load_object(ld)
        return ld

    def get_definition_path(self, ext_type, ext_name):
        target_path = ""
        if ext_type == LoadType.ROLE:
            target_path = os.path.join(
                self._path_mappings["ext_definitions"][LoadType.ROLE],
                ext_name,
            )
        elif ext_type == LoadType.COLLECTION:
            target_path = os.path.join(
                self._path_mappings["ext_definitions"][LoadType.COLLECTION],
                ext_name,
            )
        else:
            raise ValueError("Invalid ext_type")
        return target_path

    def load_definition_ext(self, target_type, target_name, target_path):
        ld = self.create_load_file(target_type, target_name, target_path)
        use_cache = True
        output_dir = self.get_definition_path(ld.target_type, ld.target_name)
        if use_cache and os.path.exists(os.path.join(output_dir, "mappings.json")):
            if not self.silent:
                logger.debug("use cache from {}".format(output_dir))
            definitions, mappings = Parser.restore_definition_objects(output_dir)
        else:
            definitions, mappings = self._parser.run(load_data=ld)
            if self.do_save:
                if output_dir == "":
                    raise ValueError("Invalid output_dir")
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)
                Parser.dump_definition_objects(output_dir, definitions, mappings)

        key = "{}-{}".format(target_type, target_name)
        self.ext_definitions[key] = {
            "definitions": definitions,
            "mappings": mappings,
        }
        return

    def _set_load_root(self, target_path=""):
        root_load_data = None
        if self.type in [LoadType.ROLE, LoadType.COLLECTION]:
            ext_type = self.type
            ext_name = self.name
            if target_path == "":
                target_path = self.get_source_path(ext_type, ext_name)
            root_load_data = self.create_load_file(ext_type, ext_name, target_path)
        elif self.type in [LoadType.PROJECT, LoadType.PLAYBOOK, LoadType.TASKFILE]:
            src_root = self.get_src_root()
            if target_path == "":
                target_path = os.path.join(src_root, escape_url(self.name))
            root_load_data = self.create_load_file(self.type, self.name, target_path)
        return root_load_data

    def get_source_path(self, ext_type, ext_name, is_ext_for_project=False):
        base_dir = ""
        if is_ext_for_project:
            base_dir = self._path_mappings["dependencies"]
        else:
            if ext_type == LoadType.ROLE:
                base_dir = os.path.join(self.root_dir, "roles", "src")
            elif ext_type == LoadType.COLLECTION:
                base_dir = os.path.join(self.root_dir, "collections", "src")

        target_path = ""
        if ext_type == LoadType.ROLE:
            target_path = os.path.join(base_dir, ext_name)
        elif ext_type == LoadType.COLLECTION:
            parts = ext_name.split(".")
            target_path = os.path.join(
                base_dir,
                "ansible_collections",
                parts[0],
                parts[1],
            )
        else:
            raise ValueError("Invalid ext_type")
        return target_path

    def load_definitions_root(self, target_path=""):

        output_dir = self._path_mappings["root_definitions"]
        root_load = self._set_load_root(target_path=target_path)

        definitions, mappings = self._parser.run(load_data=root_load, collection_name_of_project=self.collection_name)
        if self.do_save:
            if output_dir == "":
                raise ValueError("Invalid output_dir")
            if not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
            Parser.dump_definition_objects(output_dir, definitions, mappings)

        self.root_definitions = {
            "definitions": definitions,
            "mappings": mappings,
        }

    def apply_spec_mutations(self):
        if not self.spec_mutations_from_previous_scan:
            return
        # overwrite the loaded object with the mutated object in spec mutations
        for type_name in self.root_definitions["definitions"]:
            obj_list = self.root_definitions["definitions"][type_name]
            for i, obj in enumerate(obj_list):
                key = obj.key
                if key in self.spec_mutations_from_previous_scan:
                    mutated_spec = self.spec_mutations_from_previous_scan[key].object
                    self.root_definitions["definitions"][type_name][i] = mutated_spec
        return

    def set_target_object(self):
        type_name = self.type + "s"
        obj_list = self.root_definitions.get("definitions", {}).get(type_name, [])
        if len(obj_list) == 0:
            return
        elif len(obj_list) == 1:
            self.target_object = obj_list[0]
        else:
            # only for playbook / taskfile not in `--xxxx-only` mode
            for obj in obj_list:
                obj_path = getattr(obj, "defined_in")
                if self.name in obj_path:
                    self.target_object = obj
                    break
        return

    def construct_trees(self, kb_client=None):
        trees, additional, extra_requirements, resolve_failures = tree(
            self.root_definitions,
            self.ext_definitions,
            kb_client,
            self.target_playbook_name,
            self.target_taskfile_name,
            self.load_all_taskfiles,
        )

        self.trees = trees
        self.additional = additional
        self.extra_requirements = extra_requirements
        self.resolve_failures = resolve_failures

        if self.do_save:
            root_def_dir = self._path_mappings["root_definitions"]
            tree_rel_file = os.path.join(root_def_dir, "tree.json")
            if tree_rel_file != "":
                lines = []
                for t_obj_list in self.trees:
                    lines.append(t_obj_list.to_one_line_json())
                open(tree_rel_file, "w").write("\n".join(lines))
                if not self.silent:
                    logger.info("  tree file saved")
        return

    def resolve_variables(self, kb_client=None):
        taskcalls_in_trees = resolve(self.trees, self.additional)
        self.taskcalls_in_trees = taskcalls_in_trees

        if self.do_save:
            root_def_dir = self._path_mappings["root_definitions"]
            tasks_in_t_path = os.path.join(root_def_dir, "tasks_in_trees.json")
            tasks_in_t_lines = []
            for d in taskcalls_in_trees:
                line = jsonpickle.encode(d, make_refs=False)
                tasks_in_t_lines.append(line)

            open(tasks_in_t_path, "w").write("\n".join(tasks_in_t_lines))
        return

    def set_details(self, kb_client: KBClient=None):
        target_name = self.name
        if self.collection_name:
            target_name = self.collection_name
        if self.role_name:
            target_name = self.role_name

        for taskcalls_in_tree in self.taskcalls_in_trees:
            if not isinstance(taskcalls_in_tree, TaskCallsInTree):
                continue
            for taskcall in taskcalls_in_tree.taskcalls:
                set_module_details(task=taskcall)
                set_argument_key_details(task=taskcall, kb_client=kb_client)
                set_argument_value_details(task=taskcall)
                set_variable_details(task=taskcall)

        metadata = {
            "type": self.type,
            "name": target_name,
            "version": self.version,
            "source": self.source_repository,
            "download_url": self.download_url,
            "hash": self.hash,
        }
        dependencies = self.loaded_dependency_dirs

        self.findings = Findings(
            metadata=metadata,
            dependencies=dependencies,
            root_definitions=self.root_definitions,
            ext_definitions=self.ext_definitions,
            extra_requirements=self.extra_requirements,
            resolve_failures=self.resolve_failures,
            prm=self.prm,
            scan_time=datetime.datetime.utcnow().isoformat(),
        )
        return

    def add_time_records(self, time_records: dict):
        if self.findings:
            self.findings.metadata["time_records"] = time_records
        return

    def count_definitions(self):
        dep_num = len(self.loaded_dependency_dirs)
        ext_counts = {}
        for _, _defs in self.ext_definitions.items():
            for key, val in _defs.get("definitions", {}).items():
                _current = ext_counts.get(key, 0)
                _current += len(val)
                ext_counts[key] = _current
        root_counts = {}
        for key, val in self.root_definitions.get("definitions", {}).items():
            _current = root_counts.get(key, 0)
            _current += len(val)
            root_counts[key] = _current
        return dep_num, ext_counts, root_counts

    def set_metadata(self, metadata: dict, dependencies: dict):
        self.target_path = self.make_target_path(self.type, self.name)
        self.version = metadata.get("version", "")
        self.hash = metadata.get("hash", "")
        self.download_url = metadata.get("download_url", "")
        self.loaded_dependency_dirs = dependencies

    def set_metadata_findings(self):
        target_name = self.name
        if self.collection_name:
            target_name = self.collection_name
        if self.role_name:
            target_name = self.role_name
        metadata = {
            "type": self.type,
            "name": target_name,
            "version": self.version,
            "source": self.source_repository,
            "download_url": self.download_url,
            "hash": self.hash,
        }
        dependencies = self.loaded_dependency_dirs
        self.findings = Findings(
            metadata=metadata,
            dependencies=dependencies,
        )

    def load_index(self):
        index_location = self._path_mappings["index"]
        with open(index_location, "r") as f:
            self.index = json.load(f)


@dataclass
class AnsibleScanner(object):
    config: Config = None

    root_dir: str = ""

    kb_client: KBClient = None
    read_kb: bool = True
    read_kb_for_dependency: bool = True
    write_kb: bool = False

    persist_dependency_cache: bool = False

    skip_playbook_format_error: bool = (True,)
    skip_task_format_error: bool = (True,)

    use_ansible_doc: bool = True

    do_save: bool = False
    _parser: Parser = None

    show_all: bool = False
    pretty: bool = False
    silent: bool = True
    output_format: str = ""

    scan_records: dict = field(default_factory=dict)

    _current: ScanData = None

    def __post_init__(self):
        if not self.config:
            self.config = config

        if not self.root_dir:
            self.root_dir = self.config.data_dir
        if not self.kb_client:
            self.kb_client = KBClient(root_dir=self.root_dir)
        self._parser = Parser(
            do_save=self.do_save,
            use_ansible_doc=self.use_ansible_doc,
            skip_playbook_format_error=self.skip_playbook_format_error,
            skip_task_format_error=self.skip_task_format_error,
        )

        if not self.silent:
            logger.debug(f"config: {self.config}")

    def evaluate(
        self,
        type: str,
        name: str = "",
        path: str = "",
        base_dir: str = "",
        collection_name: str = "",
        role_name: str = "",
        install_dependencies: bool = True,
        use_ansible_path: bool = False,
        version: str = "",
        hash: str = "",
        target_path: str = "",
        dependency_dir: str = "",
        download_only: bool = False,
        load_only: bool = False,
        skip_dependency: bool = False,
        use_src_cache: bool = False,
        source_repository: str = "",
        playbook_yaml: str = "",
        playbook_only: bool = False,
        taskfile_yaml: str = "",
        taskfile_only: bool = False,
        raw_yaml: str = "",
        include_test_contents: bool = False,
        load_all_taskfiles: bool = False,
        yaml_label_list: list = None,
        objects: bool = False,
        out_dir: str = "",
        spec_mutations_from_previous_scan: dict = None,
        **kwargs,
    ):
        time_records = {}
        self.record_begin(time_records, "scandata_init")

        if not name and path:
            name = path

        if raw_yaml:
            if type == LoadType.PLAYBOOK:
                playbook_yaml = raw_yaml
            elif type == LoadType.TASKFILE:
                taskfile_yaml = raw_yaml

        if is_local_path(name) and not playbook_yaml and not taskfile_yaml:
            name = os.path.abspath(name)

        scandata = ScanData(
            type=type,
            name=name,
            collection_name=collection_name,
            role_name=role_name,
            install_dependencies=install_dependencies,
            use_ansible_path=use_ansible_path,
            version=version,
            hash=hash,
            target_path=target_path,
            base_dir=base_dir,
            skip_playbook_format_error=self.skip_playbook_format_error,
            skip_task_format_error=self.skip_task_format_error,
            dependency_dir=dependency_dir,
            use_src_cache=use_src_cache,
            source_repository=source_repository,
            playbook_yaml=playbook_yaml,
            playbook_only=playbook_only,
            taskfile_yaml=taskfile_yaml,
            taskfile_only=taskfile_only,
            include_test_contents=include_test_contents,
            load_all_taskfiles=load_all_taskfiles,
            yaml_label_list=yaml_label_list,
            out_dir=out_dir,
            root_dir=self.root_dir,
            persist_dependency_cache=self.persist_dependency_cache,
            spec_mutations_from_previous_scan=spec_mutations_from_previous_scan,
            use_ansible_doc=self.use_ansible_doc,
            do_save=self.do_save,
            silent=self.silent,
            _parser=self._parser,
        )
        self._current = scandata
        self.record_end(time_records, "scandata_init")

        self.record_begin(time_records, "metadata_load")
        metdata_loaded = False
        read_root_from_kb = (
            self.read_kb and scandata.type not in [LoadType.PLAYBOOK, LoadType.TASKFILE, LoadType.PROJECT] and not is_local_path(scandata.name)
        )
        if read_root_from_kb:
            loaded, metadata, dependencies = self.load_metadata_from_kb(scandata.type, scandata.name, scandata.version)
            logger.debug(f"metadata loaded: {loaded}")
            if loaded:
                scandata.set_metadata(metadata, dependencies)
                metdata_loaded = True
                if not self.silent:
                    logger.debug(f'Use metadata for "{scandata.name}" in KB')

        if scandata.install_dependencies and not metdata_loaded:
            logger.debug(f"start preparing {scandata.type} {scandata.name}")
            scandata._prepare_dependencies()
            logger.debug(f"finished preparing {scandata.type} {scandata.name}")

        if download_only:
            return None
        self.record_end(time_records, "metadata_load")

        if not skip_dependency:
            ext_list = []
            ext_list.extend(
                [
                    (
                        d.get("metadata", {}).get("type", ""),
                        d.get("metadata", {}).get("name", ""),
                        d.get("metadata", {}).get("version", ""),
                        d.get("metadata", {}).get("hash", ""),
                        d.get("dir"),
                        d.get("is_local_dir", False),
                    )
                    for d in scandata.loaded_dependency_dirs
                ]
            )
            ext_count = len(ext_list)

            # Start Ansible Scanner main flow
            self.record_begin(time_records, "dependency_load")
            for i, (ext_type, ext_name, ext_ver, ext_hash, ext_path, is_local_dir) in enumerate(ext_list):
                if not self.silent:
                    if i == 0:
                        logger.info("start loading {} {}(s)".format(ext_count, ext_type))
                    logger.info("[{}/{}] {} {}".format(i + 1, ext_count, ext_type, ext_name))

                # avoid infinite loop
                is_root = False
                if scandata.type == ext_type and scandata.name == ext_name:
                    is_root = True

                ext_target_path = os.path.join(self.root_dir, ext_path)
                role_name_for_local_dep = ""
                # if a dependency is a local role, set the local path
                if scandata.type == LoadType.ROLE and ext_type == LoadType.ROLE:
                    if is_local_dir and is_local_path(scandata.name) and scandata.name != ext_name:
                        root_role_path = scandata.name[:-1] if scandata.name[-1] == "/" else scandata.name
                        role_base_dir = os.path.dirname(root_role_path)
                        dep_role_path = os.path.join(role_base_dir, ext_name)
                        role_name_for_local_dep = ext_name
                        ext_name = dep_role_path
                        ext_target_path = dep_role_path

                if not is_root:
                    key = "{}-{}".format(ext_type, ext_name)
                    if role_name_for_local_dep:
                        key = "{}-{}".format(ext_type, role_name_for_local_dep)
                    read_kb_for_dependency = self.read_kb or self.read_kb_for_dependency

                    dep_loaded = False
                    if read_kb_for_dependency:
                        # searching findings from Ansible Scanner KB and use them if found
                        dep_loaded, ext_defs = self.load_definitions_from_kb(ext_type, ext_name, ext_ver, ext_hash)
                        if dep_loaded:
                            scandata.ext_definitions[key] = ext_defs
                            if not self.silent:
                                logger.debug(f'Use spec data for "{ext_name}" in KB')

                    if not dep_loaded:
                        # if the dependency was not found in KB and if the target path does not exist,
                        # then we give up getting dependency data here
                        if not os.path.exists(ext_target_path):
                            continue

                        # scan dependencies and save findings to Ansible Scanner KB
                        dep_scanner = AnsibleScanner(
                            root_dir=self.root_dir,
                            kb_client=self.kb_client,
                            read_kb=read_kb_for_dependency,
                            read_kb_for_dependency=self.read_kb_for_dependency,
                            write_kb=self.write_kb,
                            use_ansible_doc=self.use_ansible_doc,
                            do_save=self.do_save,
                            silent=True,
                        )
                        # use prepared dep dirs
                        dep_scanner.evaluate(
                            type=ext_type,
                            name=ext_name,
                            version=ext_ver,
                            hash=ext_hash,
                            target_path=ext_target_path,
                            dependency_dir=scandata.dependency_dir,
                            install_dependencies=False,
                            use_ansible_path=False,
                            skip_dependency=True,
                            source_repository=scandata.source_repository,
                            include_test_contents=include_test_contents,
                            load_all_taskfiles=load_all_taskfiles,
                            load_only=True,
                        )
                        dep_scandata = dep_scanner.get_last_scandata()
                        scandata.ext_definitions[key] = dep_scandata.root_definitions
                        dep_loaded = True

            self.record_end(time_records, "dependency_load")

            if not self.silent:
                logger.debug("load_definition_ext() done")

        # PRM Finder
        self.record_begin(time_records, "prm_load")
        # playbooks, roles, modules = find_playbook_role_module(scandata.target_path, self.use_ansible_doc)
        # scandata.prm["playbooks"] = playbooks
        # scandata.prm["roles"] = roles
        # scandata.prm["modules"] = modules
        self.record_end(time_records, "prm_load")

        loaded = False
        self.record_begin(time_records, "target_load")
        if read_root_from_kb:
            loaded, root_defs = self.load_definitions_from_kb(scandata.type, scandata.name, scandata.version, scandata.hash, allow_unresolved=True)
            logger.debug(f"spec data loaded: {loaded}")
            if loaded:
                scandata.root_definitions = root_defs
                if not self.silent:
                    logger.info("Use spec data in KB")
        self.record_end(time_records, "target_load")

        if not loaded:
            scandata.load_definitions_root(target_path=scandata.target_path)

        scandata.set_target_object()

        if not self.silent:
            logger.debug("load_definitions_root() done")
            playbooks_num = len(scandata.root_definitions["definitions"]["playbooks"])
            roles_num = len(scandata.root_definitions["definitions"]["roles"])
            taskfiles_num = len(scandata.root_definitions["definitions"]["taskfiles"])
            tasks_num = len(scandata.root_definitions["definitions"]["tasks"])
            modules_num = len(scandata.root_definitions["definitions"]["modules"])
            logger.debug(f"playbooks: {playbooks_num}, roles: {roles_num}, taskfiles: {taskfiles_num}, tasks: {tasks_num}, modules: {modules_num}")

        # load_only is True when this scanner is scanning dependency
        # otherwise, move on tree construction
        if load_only:
            return None

        _kb_client = None
        if self.read_kb:
            _kb_client = self.kb_client

        self.record_begin(time_records, "tree_construction")
        scandata.construct_trees(_kb_client)
        self.record_end(time_records, "tree_construction")
        if not self.silent:
            logger.debug("construct_trees() done")

        self.record_begin(time_records, "variable_resolution")
        scandata.resolve_variables(_kb_client)
        self.record_end(time_records, "variable_resolution")
        if not self.silent:
            logger.debug("resolve_variables() done")

        self.record_begin(time_records, "set_details")
        scandata.set_details(_kb_client)
        self.record_end(time_records, "set_details")
        if not self.silent:
            logger.debug("set_details() done")

        scandata.add_time_records(time_records=time_records)

        dep_num, ext_counts, root_counts = scandata.count_definitions()
        if not self.silent:
            print("# of dependencies:", dep_num)
            # print("ext definitions:", ext_counts)
            # print("root definitions:", root_counts)

        # save KB data
        if self.write_kb and scandata.type not in [LoadType.PLAYBOOK, LoadType.TASKFILE, LoadType.PROJECT]:
            self.register_findings_to_kb(scandata.findings)
            self.register_indices_to_kb(scandata.findings, include_test_contents)

        if scandata.out_dir is not None and scandata.out_dir != "":
            if objects:
                self.save_definitions(scandata.root_definitions, scandata.out_dir)
                if not self.silent:
                    print("The objects is saved at {}".format(scandata.out_dir))

        if self.pretty:
            data_str = ""
            data = json.loads(jsonpickle.encode(scandata.findings.simple(), make_refs=False))
            if self.output_format.lower() == "json":
                data_str = json.dumps(data, indent=2)
            elif self.output_format.lower() == "yaml":
                data_str = yaml.safe_dump(data)
            print(data_str)

        if scandata.spec_mutations:
            trigger_rescan = False
            _previous = spec_mutations_from_previous_scan
            if _previous and equal(scandata.spec_mutations, _previous):
                if not self.silent:
                    logger.warning("Spec mutation loop has been detected! " "Exitting the scan here but the result may be incomplete.")
            else:
                trigger_rescan = True

            if trigger_rescan:
                if not self.silent:
                    print("Spec mutations are found. Triggering Ansible scan again...")
                return self.evaluate(
                    type=type,
                    name=name,
                    path=path,
                    collection_name=collection_name,
                    role_name=role_name,
                    install_dependencies=install_dependencies,
                    use_ansible_path=use_ansible_path,
                    version=version,
                    hash=hash,
                    target_path=target_path,
                    dependency_dir=dependency_dir,
                    download_only=download_only,
                    load_only=load_only,
                    skip_dependency=skip_dependency,
                    use_src_cache=use_src_cache,
                    source_repository=source_repository,
                    playbook_yaml=playbook_yaml,
                    playbook_only=playbook_only,
                    taskfile_yaml=taskfile_yaml,
                    taskfile_only=taskfile_only,
                    include_test_contents=include_test_contents,
                    load_all_taskfiles=load_all_taskfiles,
                    objects=objects,
                    raw_yaml=raw_yaml,
                    out_dir=out_dir,
                    spec_mutations_from_previous_scan=scandata.spec_mutations,
                )

        return scandata

    def _single_scan(self, input_data, file_inventory, include_tests, out_base_dir, save_objects):
        if not isinstance(input_data, InputData):
            raise ValueError(f"input data must be InputData type, but {type(input_data)}")

        i = input_data.index
        num = input_data.total_num
        _type = input_data.type
        name = input_data.name
        path = input_data.path
        raw_yaml = input_data.yaml
        original_type = input_data.metadata.get("original_type", _type)
        base_dir = input_data.metadata.get("base_dir", None)
        kwargs = {
            "type": _type,
        }
        if path:
            kwargs["name"] = path
        if raw_yaml:
            kwargs["raw_yaml"] = raw_yaml

        source = self.scan_records.get("source", {})
        display_name = name
        if base_dir and name.startswith(base_dir):
            display_name = name.replace(base_dir, "", 1)
            if display_name and display_name[-1] == "/":
                display_name = display_name[:-1]

        yaml_label_list = []
        if file_inventory:
            for file_info in file_inventory:
                if not isinstance(file_info, dict):
                    continue
                is_yml = file_info.get("is_yml", False)
                if not is_yml:
                    continue
                fpath = file_info.get("path_from_root", "")
                label = file_info.get("label", "")
                role_info = file_info.get("role_info", {})
                if not fpath or not label:
                    continue
                yaml_label_list.append((fpath, label, role_info))

        start_of_this_scan = time.time()
        if not self.silent:
            logger.debug(f"[{i+1}/{num}] start {_type} {display_name}")
        use_src_cache = True

        taskfile_only = False
        playbook_only = False
        out_dir_basename = name
        if _type != "role" and _type != "project":
            taskfile_only = True
            playbook_only = True
            out_dir_basename = escape_local_path(name)

        scandata = None
        try:
            out_dir = ""
            if out_base_dir:
                out_dir = os.path.join(out_base_dir, _type, out_dir_basename)
            objects_option = False
            if save_objects and out_dir:
                objects_option = True
            begin = time.time()
            scandata = self.evaluate(
                **kwargs,
                install_dependencies=True,
                include_test_contents=include_tests,
                objects=objects_option,
                out_dir=out_dir,
                load_all_taskfiles=True,
                use_src_cache=use_src_cache,
                taskfile_only=taskfile_only,
                playbook_only=playbook_only,
                base_dir=base_dir,
                yaml_label_list=yaml_label_list,
            )
            elapsed = time.time() - begin
        except Exception:
            error = traceback.format_exc()
            if error:
                if not self.silent:
                    logger.error(f"Failed to scan {path} in {name}: error detail: {error}")

        if scandata:
            all_scanned_files = get_all_files_from_scandata(scandata, path)
            task_scanned_files = [fpath for fpath, scan_type in all_scanned_files if scan_type == "task"]
            play_scanned_files = [fpath for fpath, scan_type in all_scanned_files if scan_type == "play"]
            file_scanned_files = [fpath for fpath, scan_type in all_scanned_files if scan_type == "file"]
            if original_type == "project":
                if name in self.scan_records["project_file_list"]:
                    files_num = len(self.scan_records["project_file_list"][name]["files"])
                    for j in range(files_num):
                        fpath = self.scan_records["project_file_list"][name]["files"][j]["filepath"]
                        if fpath in task_scanned_files:
                            self.scan_records["project_file_list"][name]["files"][j]["task_scanned"] = True
                            self.scan_records["project_file_list"][name]["files"][j]["scanned_as"] = _type
                            self.scan_records["project_file_list"][name]["files"][j]["loaded"] = True
                        elif fpath in play_scanned_files:
                            self.scan_records["project_file_list"][name]["files"][j]["scanned_as"] = _type
                            self.scan_records["project_file_list"][name]["files"][j]["loaded"] = True
                            self.scan_records["non_task_scanned_files"].append(fpath)
                        elif fpath in file_scanned_files:
                            self.scan_records["project_file_list"][name]["files"][j]["scanned_as"] = _type
                            self.scan_records["project_file_list"][name]["files"][j]["loaded"] = True

            elif original_type == "role":
                if name in self.scan_records["role_file_list"]:
                    files_num = len(self.scan_records["role_file_list"][name]["files"])
                    for j in range(files_num):
                        fpath = self.scan_records["role_file_list"][name]["files"][j]["filepath"]
                        if fpath in task_scanned_files:
                            self.scan_records["role_file_list"][name]["files"][j]["task_scanned"] = True
                            self.scan_records["role_file_list"][name]["files"][j]["scanned_as"] = _type
                            self.scan_records["role_file_list"][name]["files"][j]["loaded"] = True
                        elif fpath in play_scanned_files:
                            self.scan_records["role_file_list"][name]["files"][j]["scanned_as"] = _type
                            self.scan_records["role_file_list"][name]["files"][j]["loaded"] = True
                            self.scan_records["non_task_scanned_files"].append(fpath)
            else:
                files_num = len(self.scan_records["independent_file_list"])
                for j in range(files_num):
                    fpath = self.scan_records["independent_file_list"][j]["filepath"]
                    if fpath in task_scanned_files:
                        self.scan_records["independent_file_list"][j]["task_scanned"] = True
                        self.scan_records["independent_file_list"][j]["scanned_as"] = _type
                        self.scan_records["independent_file_list"][j]["loaded"] = True
                    elif fpath in play_scanned_files:
                        self.scan_records["independent_file_list"][j]["scanned_as"] = _type
                        self.scan_records["independent_file_list"][j]["loaded"] = True
                        self.scan_records["non_task_scanned_files"].append(fpath)

            findings = scandata.findings
            self.scan_records["findings"].append({"target_type": _type, "target_name": name, "findings": findings})

            trees = scandata.trees
            annotation_dict = {}
            skip_annotation_keys = [
                "",
                "module.available_args",
                "variable.unnecessary_loop_vars",
            ]
            for _tree in trees:
                for call_obj in _tree.items:
                    if not hasattr(call_obj, "annotations"):
                        continue
                    orig_annotations = call_obj.annotations
                    annotations = {anno.key: anno.value for anno in orig_annotations if isinstance(anno.key, str) and anno.key not in skip_annotation_keys}
                    spec_key = call_obj.spec.key
                    if annotations:
                        annotation_dict[spec_key] = annotations

            objects = {}
            tasks = []
            plays = []
            if findings and findings.root_definitions:
                objects = findings.root_definitions.get("definitions", {})
                tasks = objects["tasks"]
                plays = objects["plays"]

            added_obj_keys = []
            for obj_type in objects:
                objects_per_type = objects[obj_type]
                for obj in objects_per_type:

                    # filter files to avoid too many files in objects
                    if obj_type == "files":
                        if is_skip_file_obj(obj, tasks, plays):
                            self.scan_records["ignored_files"].append(obj.defined_in)
                            continue

                    spec_key = obj.key
                    if spec_key in added_obj_keys:
                        continue

                    # TODO: determine whether to use VarCont
                    # obj = set_vc(obj)

                    if spec_key in annotation_dict:
                        obj.annotations = annotation_dict[spec_key]
                    self.scan_records["objects"].append(obj)
                    added_obj_keys.append(spec_key)

            self.scan_records["time"].append({"target_type": _type, "target_name": name, "scan_seconds": elapsed})

            if findings and _type == "project":
                metadata = findings.metadata.copy()
                metadata.pop("time_records")
                metadata["scan_timestamp"] = datetime.datetime.utcnow().isoformat(timespec="seconds")
                metadata["pipeline_version"] = get_scanner_version()
                self.scan_records["metadata"] = metadata

                scan_metadata = findings.metadata.copy()
                dependencies = findings.dependencies.copy()
                scan_metadata["source"] = source
                self.scan_records["scan_metadata"] = scan_metadata
                self.scan_records["dependencies"] = dependencies

        elapsed_for_this_scan = round(time.time() - start_of_this_scan, 2)
        if elapsed_for_this_scan > 60:
            if not self.silent:
                logger.warning(f"It took {elapsed_for_this_scan} sec. to process [{i+1}/{num}] {_type} {name}")

        return

    def run(self, target_dir: str="", raw_yaml: str="", **kwargs):
        self._init_scan_records()

        kwargs["target_dir"] = target_dir
        kwargs["raw_yaml"] = raw_yaml

        # source = kwargs.get("source", {})

        input_list_arg_keys = ["target_dir", "raw_yaml", "label", "filepath"]
        input_list_args = {k: v for k, v in kwargs.items() if k in input_list_arg_keys}
        input_list = self.create_input_list(**input_list_args)

        include_tests = kwargs.get("include_tests", False)
        out_base_dir = kwargs.get("out_base_dir", None)
        save_objects = kwargs.get("save_objects", False)

        file_inventory = self.create_file_inventory()

        for input_data in input_list:
            self._single_scan(
                input_data=input_data,
                file_inventory=file_inventory,
                include_tests=include_tests,
                out_base_dir=out_base_dir,
                save_objects=save_objects,
            )

        # make a list of missing files from the first scan
        missing_files = []
        for project_name in self.scan_records["project_file_list"]:
            base_dir = os.path.abspath(self.scan_records["project_file_list"][project_name]["path"])
            for file in self.scan_records["project_file_list"][project_name]["files"]:
                label = file.get("label", "")
                filepath = file.get("filepath", "")
                task_scanned = file.get("task_scanned", False)
                role_info = file.get("role_info", {})
                non_task_scanned = True if filepath in self.scan_records["non_task_scanned_files"] else False
                if not task_scanned and not non_task_scanned and label in ["playbook", "taskfile"]:
                    if role_info and role_info.get("is_external_dependency", False):
                        continue
                    _type = label
                    _name = filepath
                    missing_files.append((_type, _name, filepath, base_dir, "project"))

        for role_name in self.scan_records["role_file_list"]:
            base_dir = os.path.abspath(self.scan_records["role_file_list"][role_name]["path"])
            for file in self.scan_records["role_file_list"][role_name]["files"]:
                label = file.get("label", "")
                filepath = file.get("filepath", "")
                task_scanned = file.get("task_scanned", False)
                role_info = file.get("role_info", {})
                non_task_scanned = True if filepath in self.scan_records["non_task_scanned_files"] else False
                if not task_scanned and not non_task_scanned and label in ["playbook", "taskfile"]:
                    if role_info and role_info.get("is_external_dependency", False):
                        continue
                    _type = label
                    _name = filepath
                    missing_files.append((_type, _name, filepath, base_dir, "role"))

        self.scan_records["missing_files"] = missing_files
        num_of_missing = len(missing_files)
        second_input_list = [
            InputData(
                index=i,
                total_num=num_of_missing,
                type=_type,
                name=_name,
                path=filepath,
                metadata={"original_type": original_type, "base_dir": base_dir}
            )
            for i, (_type, _name, filepath, base_dir, original_type) in enumerate(missing_files)
        ]
        for input_data in second_input_list:
            self._single_scan(
                input_data=input_data,
                file_inventory=file_inventory,
                include_tests=include_tests,
                out_base_dir=out_base_dir,
                save_objects=save_objects,
            )

        file_inventory = self.create_file_inventory()

        result = self.create_scan_result()

        self._clear_scan_records()
        return result


    def create_input_list(self, target_dir="", raw_yaml="", label="", filepath=""):
        # single yaml scan
        if raw_yaml:
            if not label:
                label, _, error = label_yml_file(yml_body=raw_yaml)
                if error:
                    raise ValueError(f"failed to detect the input YAML type: {error}")
            if label not in ["playbook", "taskfile"]:
                raise ValueError(f"playbook and taskfile are the only supported types, but the input file is `{label}`")
            input_data = InputData(
                index=0,
                total_num=1,
                yaml=raw_yaml,
                path=filepath,
                type=label,
            )
            input_list = [input_data]

        elif target_dir:

            # otherwise, create input_list for multi-stage scan
            dir_size = get_dir_size(target_dir)
            path_list = get_yml_list(target_dir)

            project_file_list, role_file_list, independent_file_list, non_yaml_file_list = create_scan_list(path_list)
            self.scan_records["project_file_list"] = project_file_list
            self.scan_records["role_file_list"] = role_file_list
            self.scan_records["independent_file_list"] = independent_file_list
            self.scan_records["non_yaml_file_list"] = non_yaml_file_list
            self.scan_records["non_task_scanned_files"] = []
            self.scan_records["findings"] = []
            self.scan_records["metadata"] = {}
            self.scan_records["time"] = []
            self.scan_records["size"] = dir_size
            self.scan_records["objects"] = []
            self.scan_records["ignored_files"] = []

            input_list = []

            i = 0
            num = len(project_file_list) + len(role_file_list) + len(independent_file_list)
            for project_name in project_file_list:
                project_path = project_file_list[project_name].get("path")
                input_list.append(InputData(
                    index=i,
                    total_num=num,
                    type="project",
                    name=project_name,
                    path=project_path,
                    metadata={
                        "base_dir": project_path,
                    }
                ))
                i += 1

            for role_name in role_file_list:
                _type = "role"
                _name = role_name
                role_path = role_file_list[role_name].get("path")
                input_list.append(InputData(
                    index=i,
                    total_num=num,
                    type="role",
                    name=role_name,
                    path=role_path,
                    metadata={
                        "base_dir": role_path,
                    }
                ))
                i += 1

            for file in independent_file_list:
                _name = file.get("filepath")
                filepath = _name
                _type = file.get("label")
                if _type in ["playbook", "taskfile"]:
                    input_list.append(InputData(
                    index=i,
                    total_num=num,
                    type=_type,
                    name=_name,
                    path=filepath,
                    metadata={
                        "base_dir": target_dir,
                    }
                ))
                i += 1
        else:
            raise ValueError("Either `target_dir` or `raw_yaml` are required to create input_list")
        return input_list

    def create_file_inventory(self):
        file_inventory = []
        for project_name in self.scan_records["project_file_list"]:
            for file in self.scan_records["project_file_list"][project_name]["files"]:
                task_scanned = file.get("task_scanned", False)
                file["task_scanned"] = task_scanned
                scanned_as = file.get("scanned_as", "")
                file["scanned_as"] = scanned_as
                loaded = file.get("loaded", False)
                # we intentionally remove some files by is_skip_file_obj() in the current implementation
                # so set loaded=False here in that case
                if loaded:
                    in_proj_path = file.get("path_from_root", "")
                    if in_proj_path and in_proj_path in self.scan_records["ignored_files"]:
                        loaded = False
                file["loaded"] = loaded
                file_inventory.append(file)

        for role_name in self.scan_records["role_file_list"]:
            for file in self.scan_records["role_file_list"][role_name]["files"]:
                task_scanned = file.get("task_scanned", False)
                file["task_scanned"] = task_scanned
                scanned_as = file.get("scanned_as", "")
                file["scanned_as"] = scanned_as
                loaded = file.get("loaded", False)
                # we intentionally remove some files by is_skip_file_obj() in the current implementation
                # so set loaded=False here in that case
                if loaded:
                    in_proj_path = file.get("path_from_root", "")
                    if in_proj_path and in_proj_path in self.scan_records["ignored_files"]:
                        loaded = False
                file["loaded"] = loaded
                file_inventory.append(file)

        for file in self.scan_records["independent_file_list"]:
            task_scanned = file.get("task_scanned", False)
            file["task_scanned"] = task_scanned
            scanned_as = file.get("scanned_as", "")
            file["scanned_as"] = scanned_as
            loaded = file.get("loaded", False)
            # we intentionally remove some files by is_skip_file_obj() in the current implementation
            # so set loaded=False here in that case
            if loaded:
                in_proj_path = file.get("path_from_root", "")
                if in_proj_path and in_proj_path in self.scan_records["ignored_files"]:
                    loaded = False
            file["loaded"] = loaded
            file_inventory.append(file)

        for file in self.scan_records["non_yaml_file_list"]:
            task_scanned = file.get("task_scanned", False)
            file["task_scanned"] = task_scanned
            scanned_as = file.get("scanned_as", "")
            file["scanned_as"] = scanned_as
            loaded = file.get("loaded", False)
            # we intentionally remove some files by is_skip_file_obj() in the current implementation
            # so set loaded=False here in that case
            if loaded:
                in_proj_path = file.get("path_from_root", "")
                if in_proj_path and in_proj_path in self.scan_records["ignored_files"]:
                    loaded = False
            file["loaded"] = loaded
            file_inventory.append(file)

        return file_inventory

    def create_scan_result(self):
        if not self.scan_records:
            return
        source = self.scan_records.get("source", {})
        file_inventory = self.file_inventory
        objects = self.scan_records.get("objects", [])
        metadata = self.scan_records.get("metadata", {})
        scan_time = self.scan_records.get("time", [])
        dir_size = self.scan_records.get("size", 0)
        scan_metadata = self.scan_records.get("scan_metadata", {})
        dependencies = self.scan_records.get("dependencies", [])
        proj = ScanResult.from_source_objects(
            source=source,
            file_inventory=file_inventory,
            objects=objects,
            metadata=metadata,
            scan_time=scan_time,
            dir_size=dir_size,
            scan_metadata=scan_metadata,
            dependencies=dependencies,
        )
        return proj

    def _init_scan_records(self):
        self.scan_records = {
            "project_file_list": {},
            "role_file_list": {},
            "independent_file_list": [],
            "non_yaml_file_list": [],
            "non_task_scanned_files": [],
            "findings": [],
            "metadata": {},
            "time": [],
            "size": 0,
            "objects": [],
            "ignored_files": [],
            "begin": time.time(),
        }
        self.file_inventory = []
        return

    def _clear_scan_records(self):
        self.scan_records = {}
        return

    def load_metadata_from_kb(self, type, name, version):
        loaded, metadata, dependencies = self.kb_client.load_metadata_from_findings(type, name, version)
        return loaded, metadata, dependencies

    def load_definitions_from_kb(self, type, name, version, hash, allow_unresolved=False):
        loaded, definitions, mappings = self.kb_client.load_definitions_from_findings(type, name, version, hash, allow_unresolved)
        definitions_dict = {}
        if loaded:
            definitions_dict = {
                "definitions": definitions,
                "mappings": mappings,
            }
        return loaded, definitions_dict

    def register_findings_to_kb(self, findings: Findings):
        self.kb_client.register(findings)

    def register_indices_to_kb(self, findings: Findings, include_test_contents: bool = False):
        self.kb_client.register_indices_to_kb(findings, include_test_contents)

    def save_findings(self, findings: Findings, out_dir: str):
        self.kb_client.save_findings(findings, out_dir)

    def save_definitions(self, definitions: dict, out_dir: str):
        if out_dir == "":
            raise ValueError("output dir must be a non-empty value")

        if not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)

        objects_json_str = jsonpickle.encode(definitions["definitions"], make_refs=False)
        fpath = os.path.join(out_dir, "objects.json")
        with open(fpath, "w") as file:
            file.write(objects_json_str)

    def get_last_scandata(self):
        return self._current

    def save_error(self, error: str, out_dir: str = ""):
        if out_dir == "":
            type = self._current.type
            name = self._current.name
            version = self._current.version
            hash = self._current.hash
            out_dir = self.kb_client.make_findings_dir_path(type, name, version, hash)
        self.kb_client.save_error(error, out_dir)

    def record_begin(self, time_records: dict, record_name: str):
        time_records[record_name] = {}
        time_records[record_name]["begin"] = datetime.datetime.utcnow().isoformat()

    def record_end(self, time_records: dict, record_name: str):
        end = datetime.datetime.utcnow()
        time_records[record_name]["end"] = end.isoformat()
        begin = datetime.datetime.fromisoformat(time_records[record_name]["begin"])
        elapsed = (end - begin).total_seconds()
        time_records[record_name]["elapsed"] = elapsed


def tree(root_definitions, ext_definitions, kb_client=None, target_playbook_path=None, target_taskfile_path=None, load_all_taskfiles=False):
    tl = TreeLoader(root_definitions, ext_definitions, kb_client, target_playbook_path, target_taskfile_path, load_all_taskfiles)
    trees, additional = tl.run()
    if trees is None:
        raise ValueError("failed to get trees")
    # if node_objects is None:
    #     raise ValueError("failed to get node_objects")
    return (
        trees,
        additional,
        tl.extra_requirements,
        tl.resolve_failures,
    )


def resolve(trees, additional):
    taskcalls_in_trees = []
    for i, tree in enumerate(trees):
        if not isinstance(tree, ObjectList):
            continue
        if len(tree.items) == 0:
            continue
        root_key = tree.items[0].spec.key
        logger.debug("[{}/{}] {}".format(i + 1, len(trees), root_key))
        taskcalls = resolve_variables(tree, additional)
        d = TaskCallsInTree(
            root_key=root_key,
            taskcalls=taskcalls,
        )
        taskcalls_in_trees.append(d)
    return taskcalls_in_trees


def get_all_files_from_scandata(scandata, scan_root_dir):
    
    task_specs = scandata.root_definitions.get("definitions", {}).get("tasks", [])
    all_files = []
    for task_spec in task_specs:
        fullpath = os.path.join(scan_root_dir, task_spec.defined_in)
        if fullpath not in all_files:
            all_files.append((fullpath, "task"))

    # some plays have only `roles` instead of `tasks`
    # count this type of playbook files here
    play_specs = scandata.root_definitions.get("definitions", {}).get("plays", [])
    for play_spec in play_specs:
        fullpath = os.path.join(scan_root_dir, play_spec.defined_in)
        if fullpath not in all_files:
            all_files.append((fullpath, "play"))

    file_specs = scandata.root_definitions.get("definitions", {}).get("files", [])
    for file_spec in file_specs:
        fullpath = os.path.join(scan_root_dir, file_spec.defined_in)
        if fullpath not in all_files:
            all_files.append((fullpath, "file"))
    return all_files


if __name__ == "__main__":
    __target_type = sys.argv[1]
    __target_name = sys.argv[2]
    __dependency_dir = ""
    if len(sys.argv) >= 4:
        __dependency_dir = sys.argv[3]
    c = AnsibleScanner(
        root_dir=config.data_dir,
    )
    c.evaluate(
        type=__target_type,
        name=__target_name,
        dependency_dir=__dependency_dir,
    )
