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

"""bonnet.article subject/body validation at the KindValidator layer.

A blank subject used to pass `_validate_article` as long as metadata field 1
was present at all (`m.get_text(1) is None` only catches a missing field, not
an empty or whitespace-only string) - this is the server-side half of the
empty-subject fix; tests/test_gateway_tool_arg_validation.py covers the
gateway-side belt-and-suspenders check on the same rule. An empty body stays
allowed - body_size is never checked here.
"""

import pytest

from bonnet.core.crypto import Identity
from bonnet.core.kind_validator import KindValidator, ValidationError
from bonnet.core.record import ZERO_HASH, Intent, MetadataMap, metadata_text

ORIGIN = "bbs.test"
ACTOR = Identity.from_private_key(bytes(range(10, 42)))


def _article_intent(subject, *, content_type="text/plain", body=b""):
    return Intent(
        event_id=bytes(range(1, 33)),
        kind="bonnet.article",
        origin=ORIGIN,
        actor_pubkey=ACTOR.public_key,
        board="general",
        article_id=bytes(range(2, 34)),
        metadata=MetadataMap([metadata_text(1, subject), metadata_text(4, content_type)]),
        body_hash=ZERO_HASH,
        body_size=len(body),
    )


@pytest.fixture
def validator():
    return KindValidator()


class TestArticleSubject:
    def test_rejects_missing_subject_field(self, validator):
        intent = Intent(
            event_id=bytes(range(1, 33)),
            kind="bonnet.article",
            origin=ORIGIN,
            actor_pubkey=ACTOR.public_key,
            board="general",
            article_id=bytes(range(2, 34)),
            metadata=MetadataMap([metadata_text(4, "text/plain")]),
            body_hash=ZERO_HASH,
            body_size=0,
        )
        with pytest.raises(ValidationError, match="subject"):
            validator.validate(intent)

    def test_rejects_empty_subject(self, validator):
        with pytest.raises(ValidationError, match="non-empty subject"):
            validator.validate(_article_intent(""))

    def test_rejects_whitespace_only_subject(self, validator):
        with pytest.raises(ValidationError, match="non-empty subject"):
            validator.validate(_article_intent("   \t\n  "))

    def test_accepts_non_blank_subject(self, validator):
        validator.validate(_article_intent("Hello"))

    def test_accepts_empty_body(self, validator):
        """Empty article bodies are allowed - only the subject is required."""
        validator.validate(_article_intent("Hello", body=b""))
