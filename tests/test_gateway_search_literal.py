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

"""search_articles(regex=False) sends body_query to ripgrep as literal text."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from bonnet.gateway import tools

TEXTS = [
    "[bnt:sys.example/00ff]",
    r"a.b+c*d?e(f)g|h[i]j{k}l^m$n#o&p-q~r\s",
    "plain words",
    "",
]


def test_literal_escapes_every_metacharacter():
    assert tools._rg_literal("[bnt:") == r"\[bnt:"
    assert tools._rg_literal("plain words") == "plain words"


@pytest.mark.skipif(shutil.which("rg") is None, reason="ripgrep not installed")
@pytest.mark.parametrize("text", [t for t in TEXTS if t])
def test_ripgrep_matches_the_escaped_text_literally(tmp_path, text):
    f = tmp_path / "body"
    f.write_text(f"before {text} after\n")
    decoy = tmp_path / "decoy"
    decoy.write_text("nothing like it\n")
    proc = subprocess.run(
        ["rg", "-l", "--", tools._rg_literal(text), str(tmp_path)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == [str(f)]


async def test_body_query_is_escaped_unless_regex(monkeypatch):
    sent = []

    class Client:
        async def search_articles(self, origin, board, query, body_query, offset, limit):
            sent.append(body_query)

        async def close(self):
            pass

    async def connect(client, auth):
        pass

    monkeypatch.setattr(tools, "_make_client", Client)
    monkeypatch.setattr(tools, "_connect_with_default", connect)
    monkeypatch.setattr(tools.cursor, "resolve_board", lambda board: board or "b")
    await tools.search_articles("", body_query="[bnt:")
    await tools.search_articles("", body_query="bnt:[0-9a-f]+", regex=True)
    assert sent == [r"\[bnt:", "bnt:[0-9a-f]+"]
