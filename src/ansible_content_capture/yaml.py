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

import io
from contextvars import ContextVar
from ruamel.yaml import YAML
from ruamel.yaml.emitter import EmitterError


_yaml: ContextVar[YAML] = ContextVar("yaml")


def _set_yaml(force=False):
    if not _yaml.get(None) or force:
        yaml = YAML(typ="rt", pure=True)
        yaml.default_flow_style = False
        yaml.preserve_quotes = True
        yaml.allow_duplicate_keys = True
        yaml.width = 1024
        _yaml.set(yaml)


def config(**kwargs):
    _set_yaml()
    yaml = _yaml.get()
    for key, value in kwargs.items():
        setattr(yaml, key, value)
    _yaml.set(yaml)


def indent(**kwargs):
    _set_yaml()
    yaml = _yaml.get()
    yaml.indent(**kwargs)
    _yaml.set(yaml)


def load(stream: any):
    _set_yaml()
    yaml = _yaml.get()
    return yaml.load(stream)


# `ruamel.yaml` has a bug around multi-threading, and its YAML() instance could be broken
# while concurrent dump() operation. So we try retrying if the specific error occurs.
# Bug details: https://sourceforge.net/p/ruamel-yaml/tickets/367/
def dump(data: any):
    _set_yaml()
    retry = 2
    err = None
    result = None
    for i in range(retry):
        try:
            yaml = _yaml.get()
            output = io.StringIO()
            yaml.dump(data, output)
            result = output.getvalue()
        except EmitterError as exc:
            err = exc
        except Exception:
            raise
        if err:
            if i < retry - 1:
                _set_yaml(force=True)
                err = None
            else:
                raise err
        else:
            break
    return result
