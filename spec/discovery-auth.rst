Discovery and Request Signing
===============================

Fetch the manifest first. Sign every request.

Manifest
========

Read the manifest at ``GET /.well-known/untp`` before you send a command. You find the server code in ``src/bonnet/net/firehose_http_server.py``.

.. list-table:: Manifest fields
   :header-rows: 1

   * - Name
     - Shape
   * - protocol
     - always ``untp-1``
   * - origin
     - origin name
   * - hostname
     - server host name
   * - public_key
     - origin key as lower case hex
   * - anonymous_key
     - shared read key as lower case hex
   * - anonymous_private_key
     - shared read secret as lower case hex
   * - command_endpoint
     - always ``/command``
   * - known_origins
     - sorted names of the origin plus peers
   * - capabilities
     - feature flags
   * - signature_lifetime_seconds
     - integer, default 300
   * - clock_skew_seconds
     - integer, default 300

1. Pin the origin key on first sight.
2. Refuse a second key for the same origin with no rotation proof.

Requests
========

Send commands as ``POST /command`` with type ``application/vnd.bonnet.command``. Sign each call in the RFC 9421 profile. You find the auth code in ``src/bonnet/net/http_auth.py``.

Cover these fields in each request signature:

- ``@method``
- ``@authority``
- ``@target-uri``
- ``content-type``
- ``content-digest``
- ``untp-version``
- ``untp-nonce``

1. Set ``untp-version`` to ``1``.
2. Set the request nonce to 32 fresh bytes in base64url form with no padding.
3. Copy the same nonce into the signature hint and the ``untp-nonce`` field.
4. Set the tag hint to ``untp-1``. Set the mark hint to ``untp``.
5. Set the key hint to ``ed25519:`` plus your lower case hex key.
6. Set the time hints inside a 300 second life with a 300 second skew.
7. Hash the body as ``sha-256=:base64:``. Cover the digest.

Responses
=========

The cover set below applies to ``POST /command`` responses. Discovery
(``GET /.well-known/untp``) carries no request nonce, so its signature is
checked for math only, not for header coverage.

Cover these fields in each command response signature:

- ``@status``
- ``content-type``
- ``content-digest``
- ``untp-version``
- ``untp-origin``
- ``untp-request-nonce``

1. Check the response key hint of form ``origin:`` plus the origin name.
2. Check that ``untp-request-nonce`` is your request nonce.
3. Check the digest against the body bytes.
4. Treat a miss on any check as a transport fault.
