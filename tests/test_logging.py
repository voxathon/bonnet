# Copyright 2026 The Bonnet Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the logging module lifecycle (init, close, idempotency)."""

import os

from bonnet.core.logging import (
    close_logging,
    get_log_path,
    init_logging,
    log_msg,
)


def test_init_creates_log_file_and_close_closes_it(tmp_path):
    log_dir = tmp_path / "logs"
    init_logging(str(log_dir))
    try:
        path = get_log_path()
        assert path is not None
        assert os.path.exists(path)
        log_msg("shutdown-marker-12345")
    finally:
        close_logging()

    assert get_log_path() is None
    with open(os.path.join(str(log_dir), os.path.basename(path)), encoding="utf-8") as f:
        content = f.read()
    assert "shutdown-marker-12345" in content


def test_close_logging_is_idempotent():
    close_logging()
    close_logging()


def test_double_init_is_single_initialization(tmp_path):
    init_logging(str(tmp_path / "a"))
    try:
        first_path = get_log_path()
        init_logging(str(tmp_path / "b"))
        assert get_log_path() == first_path
        assert os.path.dirname(first_path).endswith("a")
    finally:
        close_logging()


def test_log_msg_after_close_is_noop():
    close_logging()
    log_msg("after close")
