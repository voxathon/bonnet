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

"""Every built-in venue adapter, one folder per venue type.

Each `<type>/` holds the adapter (`adapter.py`, its class exported from the
package), a fake of the venue for tests (`fake.py`), and a README on the
venue's quirks. `README.md` here says how to add one.

Import-light on purpose: `bonnet.bridges.adapter` reads these tables to
load a venue's adapter only when a config names that venue.
"""

# Venue type -> "module:Class" of its adapter.
BUILTIN_ADAPTERS = {
    "flatboard": "bonnet.bridges.adapters.flatboard:FlatboardAdapter",
}

# Venue type -> "module:Class" of its fake venue (bonnet.bridges.conformance).
# Every built-in adapter has one: it's how the conformance suite reaches it.
BUILTIN_FAKES = {
    "flatboard": "bonnet.bridges.adapters.flatboard.fake:FakeFlatboard",
}
