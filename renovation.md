# Renovation Plan: TLS 1.3 + RPK + Ed25519/X25519

Replace custom `iixp.pyx` protocol with standards-compliant TLS 1.3 using OpenSSL 3.2+ Raw Public Keys (RFC 7250).

---

## Background

### Current State: iixp.pyx

Custom encrypted protocol with:
- **Handshake**: Custom frames (CLIENT_HELLO, SERVER_HELLO, etc.)
- **Encryption**: ChaCha20-Poly1305 AEAD (via PyNaCl/libsodium)
- **Key Exchange**: X25519 ECDH
- **Signatures**: Ed25519
- **Key Derivation**: Custom HKDF-SHA256
- **Transport**: Raw TCP with custom 26-byte frame header

**Issues:**
- Not TLS-compliant (won't interop with standard TLS clients/servers)
- Custom protocol = more surface for bugs
- Reinventing cryptographic handshake

### Target: TLS 1.3 + RPK

- **RFC 7250**: Raw Public Keys in TLS/DTLS
- **OpenSSL 3.2+**: Native RPK support (added Oct 2023)
- **Ed25519**: Authentication (signatures)
- **X25519**: Key exchange (TLS 1.3 default)
- **No X.509**: No certificate bloat, no CA infrastructure

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  src/tls.pyx - libssl shim for RPK                       │
├─────────────────────────────────────────────────────────┤
│  • BIO pair for raw TCP socket control                  │
│  • OpenSSL 3.2+ RPK APIs (no X.509)                    │
│  • Ed25519 identity keys (32-byte raw format)           │
│  • X25519 key exchange (TLS 1.3 default)               │
│  • Key pinning via SSL_add_expected_rpk()              │
│  • Runtime OpenSSL version check                        │
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│  OpenSSL 3.2+ (system libssl)                           │
└─────────────────────────────────────────────────────────┘
```

---

## File Changes

| File | Action |
|------|--------|
| `src/tls.pyx` | **CREATE** - OpenSSL RPK implementation |
| `src/iixp.pyx` | **DELETE** |
| `src/bonnet.pyx` | **UPDATE** - change import from `iixp` to `tls` |
| `Makefile` | **UPDATE** - add OpenSSL linking, replace iixp with tls |
| `pyproject.toml` | **UPDATE** - remove `pynacl` dependency |

---

## Public API

### Identity Class

```python
class Identity:
    """Ed25519 keypair for TLS authentication"""
    
    @staticmethod
    def generate() -> Identity:
        """Generate new Ed25519 keypair"""
        
    @staticmethod
    def from_private_key(bytes key) -> Identity:
        """Load from 32-byte raw private key"""
        
    @property
    def public_key(self) -> bytes:
        """32-byte raw public key"""
```

### Session Class

```python
class Session:
    """Established TLS 1.3 connection with RPK"""
    
    def recv(self) -> bytes:
        """Receive decrypted application data"""
        
    def send(self, bytes data):
        """Send encrypted application data"""
        
    def close(self, int code=0, str reason=""):
        """Close TLS connection"""
        
    @property
    def peer_identity(self) -> bytes:
        """Peer's 32-byte Ed25519 public key"""
```

### Handshake Functions

```python
def connect(
    socket sock,
    Identity client_identity,
    bytes server_pinned = None
) -> Session:
    """
    TLS 1.3 client handshake with RPK.
    
    Args:
        sock: Connected TCP socket
        client_identity: Client's Ed25519 keypair
        server_pinned: Optional pinned server public key (32 bytes)
    
    Returns:
        Session with established TLS connection
    
    Raises:
        TLSError: Handshake failed
        PeerVerificationError: Server RPK doesn't match pinned key
    """

def accept(
    socket sock,
    Identity server_identity,
    bytes client_pinned = None
) -> Session:
    """
    TLS 1.3 server handshake with RPK (mTLS).
    
    Args:
        sock: Bound/listening TCP socket (will accept)
        server_identity: Server's Ed25519 keypair
        client_pinned: Optional pinned client public key (32 bytes)
    
    Returns:
        Session with established TLS connection
    
    Raises:
        TLSError: Handshake failed
        PeerVerificationError: Client RPK doesn't match pinned key
    """
```

### Exceptions

```python
class TLSError(OSError):
    """TLS operation failed"""
    
    def __init__(self, message, ssl_error=0, openssl_error=""):
        self.ssl_error = ssl_error      # SSL_ERROR_* constant
        self.openssl_error = openssl_error  # ERR_error_string()

class HandshakeError(TLSError):
    """Handshake failed"""

class PeerVerificationError(TLSError):
    """Peer RPK not trusted"""
```

---

## Implementation Details

### OpenSSL Version Check

```cython
cdef extern from "openssl/ssl.h":
    unsigned long OpenSSL_version_num()
    const char *OpenSSL_version(int type)
    int OPENSSL_VERSION

cdef void _check_openssl_version():
    cdef unsigned long version = OpenSSL_version_num()
    # OpenSSL 3.2.0 = 0x30200000
    if version < 0x30200000:
        raise RuntimeError(
            f"OpenSSL 3.2+ required for RPK support. "
            f"Found: {OpenSSL_version(OPENSSL_VERSION)}"
        )
```

### TLS Context Setup

```cython
cdef extern from "openssl/ssl.h":
    ctypedef struct SSL_CTX
    ctypedef struct SSL_METHOD
    
    SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
    const SSL_METHOD *TLS_server_method()
    const SSL_METHOD *TLS_client_method()
    
    int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version)
    int SSL_CTX_set1_server_cert_type(SSL_CTX *ctx, const unsigned char *val, size_t len)
    int SSL_CTX_set1_client_cert_type(SSL_CTX *ctx, const unsigned char *val, size_t len)
    
    int TLS1_3_VERSION
    int TLSEXT_cert_type_rpk  # = 0x1000

cdef SSL_CTX *_create_context(bint is_server):
    cdef SSL_CTX *ctx = SSL_CTX_new(
        TLS_server_method() if is_server else TLS_client_method()
    )
    if not ctx:
        raise MemoryError("Failed to create SSL_CTX")
    
    # TLS 1.3 only
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)
    
    # RPK only, no X.509
    cdef unsigned char cert_types[1]
    cert_types[0] = <unsigned char>TLSEXT_cert_type_rpk
    SSL_CTX_set1_server_cert_type(ctx, cert_types, 1)
    SSL_CTX_set1_client_cert_type(ctx, cert_types, 1)
    
    return ctx
```

### BIO Pair for Raw TCP

```cython
cdef extern from "openssl/bio.h":
    ctypedef struct BIO
    int BIO_new_bio_pair(BIO **bio1, size_t writebuf1, BIO **bio2, size_t writebuf2)
    int BIO_read(BIO *b, void *buf, int len)
    int BIO_write(BIO *b, const void *buf, int len)
    size_t BIO_ctrl_pending(BIO *b)
    void BIO_free_all(BIO *bio)

cdef extern from "openssl/ssl.h":
    void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio)

cdef void _setup_bio_pair(SSL *ssl, BIO **net_bio_out):
    cdef BIO *ssl_bio = NULL
    cdef BIO *net_bio = NULL
    
    if BIO_new_bio_pair(&ssl_bio, 0, &net_bio, 8192) != 1:
        raise MemoryError("Failed to create BIO pair")
    
    SSL_set_bio(ssl, ssl_bio, ssl_bio)
    net_bio_out[0] = net_bio
```

### Identity from Raw Ed25519 Key

```cython
cdef extern from "openssl/evp.h":
    ctypedef struct EVP_PKEY
    ctypedef struct EVP_PKEY_CTX
    
    EVP_PKEY *EVP_PKEY_new_raw_private_key(
        OSSL_LIB_CTX *libctx,
        const char *keytype,
        const OSSL_PARAM *params,
        const unsigned char *key,
        size_t keylen
    )
    int EVP_PKEY_get_raw_public_key(EVP_PKEY *pkey, unsigned char *pub, size_t *len)
    void EVP_PKEY_free(EVP_PKEY *pkey)

cdef class Identity:
    cdef EVP_PKEY *_pkey
    cdef unsigned char _public_key[32]
    
    @staticmethod
    def from_private_key(bytes key not None):
        if len(key) != 32:
            raise ValueError("Ed25519 private key must be 32 bytes")
        
        cdef Identity ident = Identity()
        ident._pkey = EVP_PKEY_new_raw_private_key(
            NULL,       # default context
            "ED25519",
            NULL,       # no params
            <unsigned char*>key,
            32
        )
        if not ident._pkey:
            raise TLSError("Failed to load Ed25519 key", 0, _get_openssl_error())
        
        # Extract public key
        cdef size_t publen = 32
        EVP_PKEY_get_raw_public_key(ident._pkey, ident._public_key, &publen)
        
        return ident
    
    @property
    def public_key(self):
        return bytes(self._public_key[:32])
```

### Handshake Pump

```cython
cdef extern from "openssl/ssl.h":
    int SSL_do_handshake(SSL *ssl)
    int SSL_is_init_finished(SSL *ssl)
    int SSL_get_error(SSL *ssl, int ret)
    int SSL_ERROR_WANT_READ
    int SSL_ERROR_WANT_WRITE
    int SSL_ERROR_SSL

cdef Session _do_handshake(
    SSL *ssl,
    BIO *net_bio,
    object sock,
    bint is_server,
    bytes peer_pinned
):
    cdef int ret, err
    cdef char buf[8192]
    cdef int buflen
    
    while not SSL_is_init_finished(ssl):
        ret = SSL_do_handshake(ssl)
        err = SSL_get_error(ssl, ret)
        
        if err == SSL_ERROR_WANT_READ:
            # Need data from network
            buflen = sock.recv_into(buf, 8192)
            if buflen <= 0:
                raise HandshakeError("Connection closed during handshake")
            BIO_write(net_bio, buf, buflen)
            
        elif err == SSL_ERROR_WANT_WRITE:
            # Need to send data to network
            buflen = BIO_ctrl_pending(net_bio)
            if buflen > 0:
                buflen = BIO_read(net_bio, buf, buflen)
                if buflen > 0:
                    sock.sendall(PyBytes_FromStringAndSize(buf, buflen))
                    
        elif err == SSL_ERROR_SSL:
            raise HandshakeError(
                "TLS handshake failed",
                err,
                _get_openssl_error()
            )
        else:
            raise HandshakeError(
                f"Handshake error: {err}",
                err,
                _get_openssl_error()
            )
    
    # Verify peer if pinned
    if peer_pinned:
        result = SSL_get_verify_result(ssl)
        if result != X509_V_OK:
            raise PeerVerificationError(
                "Peer RPK verification failed",
                result,
                _get_openssl_error()
            )
    
    # Extract peer identity
    cdef EVP_PKEY *peer_rpk = SSL_get0_peer_rpk(ssl)
    if not peer_rpk:
        raise HandshakeError("No peer RPK received")
    
    cdef unsigned char peer_pub[32]
    cdef size_t peer_pub_len = 32
    EVP_PKEY_get_raw_public_key(peer_rpk, peer_pub, &peer_pub_len)
    
    return Session(ssl, net_bio, sock, bytes(peer_pub[:32]))
```

### mTLS Configuration

```cython
cdef extern from "openssl/ssl.h":
    int SSL_set_verify(SSL *ssl, int mode, void *callback)
    int SSL_add_expected_rpk(SSL *ssl, EVP_PKEY *rpk)
    int SSL_get_verify_result(SSL *ssl)
    int X509_V_OK
    int X509_V_ERR_RPK_UNTRUSTED

# Server side
SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL)

# Pin expected peer RPK
SSL_add_expected_rpk(ssl, pinned_pkey)
```

### Session I/O

```cython
cpdef bytes Session.recv(self):
    # Pump incoming data from socket to BIO
    cdef char net_buf[8192]
    cdef int net_len
    
    while True:
        # Check if SSL has data ready
        buflen = SSL_pending(self._ssl)
        if buflen > 0:
            break
        
        # Check if BIO has pending data
        if BIO_ctrl_pending(self._net_bio) > 0:
            break
        
        # Need more data from socket
        net_len = self._sock.recv_into(net_buf, 8192)
        if net_len <= 0:
            return b""  # Connection closed
        BIO_write(self._net_bio, net_buf, net_len)
    
    # Read decrypted data
    cdef char app_buf[16384]
    cdef int app_len = SSL_read(self._ssl, app_buf, 16384)
    
    if app_len < 0:
        err = SSL_get_error(self._ssl, app_len)
        if err == SSL_ERROR_ZERO_RETURN:
            return b""  # Clean shutdown
        raise TLSError("SSL_read failed", err, _get_openssl_error())
    
    return PyBytes_FromStringAndSize(app_buf, app_len)

cpdef void Session.send(self, bytes data):
    cdef int ret = SSL_write(self._ssl, <char*>data, len(data))
    if ret < 0:
        raise TLSError("SSL_write failed", SSL_get_error(self._ssl, ret), _get_openssl_error())
    
    # Pump outgoing data from BIO to socket
    cdef char net_buf[8192]
    cdef int net_len
    cdef size_t pending
    
    while True:
        pending = BIO_ctrl_pending(self._net_bio)
        if pending == 0:
            break
        
        net_len = BIO_read(self._net_bio, net_buf, min(pending, 8192))
        if net_len > 0:
            self._sock.sendall(PyBytes_FromStringAndSize(net_buf, net_len))
```

---

## Makefile Changes

```makefile
# OpenSSL pkg-config
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null || echo "")
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

# Updated flags
CFLAGS := -O3 -I$(PYTHON_INCLUDE) $(OPENSSL_CFLAGS)
LDFLAGS := -L$(PYTHON_LIBDIR) -lpython3.12 $(OPENSSL_LIBS) -Wl,-rpath,$(PYTHON_LIBDIR)

# Update module list
MODULES := orm ame ume tls __init  # removed iixp, added tls

# Add tls.c target
$(BUILD_DIR)/tls.c: $(SRC_DIR)/tls.pyx | $(BUILD_DIR)
	$(CYTHON) -3 $< -o $@

$(BUILD_DIR)/tls.so: $(BUILD_DIR)/tls.c
	$(CLANG) -shared -fPIC $(CFLAGS) $< -o $@

# Update bonnet binary target
$(BIN_DIR)/bonnet: $(BUILD_DIR)/bonnet_embed.c $(BUILD_DIR)/orm.so $(BUILD_DIR)/ame.so $(BUILD_DIR)/ume.so $(BUILD_DIR)/tls.so $(BUILD_DIR)/__init.so | $(BIN_DIR)
	$(CLANG) $(CFLAGS) $(BUILD_DIR)/bonnet_embed.c -o $@.bin $(LDFLAGS)
	cp $(BUILD_DIR)/*.so $(BIN_DIR)/
	@printf '#!/bin/bash\nSCRIPT_DIR="$$(cd "$$(dirname "$$0")" && pwd)"\nVENV_DIR="$$(cd "$${SCRIPT_DIR}/.." && pwd)/.venv"\nPYTHONPATH="$${VENV_DIR}/lib/python3.12/site-packages:$${SCRIPT_DIR}"\nexport PYTHONPATH\nexec "$${SCRIPT_DIR}/bonnet.bin" "$$@"\n' > $@
	@chmod +x $@
```

---

## pyproject.toml Changes

```toml
dependencies = [
    "cython>=3.2.4",
    # Removed: "pynacl>=1.5.0"
    "pyinstaller>=6.0.0",
]
```

---

## bonnet.pyx Changes

```cython
# Before:
from iixp import accept, Session, FRAME_APP_DATA, FRAME_CLOSE

# After:
from tls import accept, Session, TLSError

# FRAME_APP_DATA and FRAME_CLOSE no longer needed
# TLS handles message framing internally
```

---

## Key OpenSSL RPK APIs Reference

```c
// Certificate type configuration
int SSL_CTX_set1_server_cert_type(SSL_CTX *ctx, const unsigned char *val, size_t len);
int SSL_CTX_set1_client_cert_type(SSL_CTX *ctx, const unsigned char *val, size_t len);
int SSL_set1_server_cert_type(SSL *ssl, const unsigned char *val, size_t len);
int SSL_set1_client_cert_type(SSL *ssl, const unsigned char *val, size_t len);

// Certificate type values
#define TLSEXT_cert_type_rpk  0x1000  // Raw Public Key
#define TLSEXT_cert_type_x509 0       // X.509 Certificate

// Use raw key (no certificate needed!)
int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey);
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);

// Pin expected peer RPK
int SSL_add_expected_rpk(SSL *ssl, EVP_PKEY *rpk);

// Get peer RPK after handshake
EVP_PKEY *SSL_get0_peer_rpk(const SSL *ssl);

// Verification result
int SSL_get_verify_result(SSL *ssl);
// Returns X509_V_OK (0) if RPK matches
// Returns X509_V_ERR_RPK_UNTRUSTED if no match

// Raw key operations
EVP_PKEY *EVP_PKEY_new_raw_private_key(OSSL_LIB_CTX *libctx, const char *keytype,
                                        const OSSL_PARAM *params,
                                        const unsigned char *key, size_t keylen);
int EVP_PKEY_get_raw_public_key(EVP_PKEY *pkey, unsigned char *pub, size_t *len);

// Key types
"ED25519"  // Ed25519 signature key
"X25519"   // X25519 key agreement key
```

---

## TLS 1.3 Handshake with RPK

```
Client                                          Server
------                                          ------
ClientHello
  + supported_versions(1.3)
  + supported_groups(X25519)
  + signature_algorithms(ed25519)
  + server_certificate_type(RPK)
  + client_certificate_type(RPK) [for mTLS]
                                            ->

                                          <- ServerHello
                                             + server_certificate_type(RPK)
                                             + client_certificate_type(RPK) [for mTLS]
                                             Certificate (SubjectPublicKeyInfo)
                                             CertificateVerify
                                             Finished

Certificate (SubjectPublicKeyInfo)
CertificateVerify
Finished                                     ->

Application Data <=========> Application Data
```

Note: TLS 1.3 has only 1-RTT handshake (2 messages each direction).

---

## Testing Checklist

- [ ] OpenSSL 3.2+ installed on build system
- [ ] OpenSSL < 3.2 fails with clear error message
- [ ] Ed25519 key loading (32-byte raw format)
- [ ] TLS 1.3 handshake without peer pinning
- [ ] TLS 1.3 handshake with peer pinning (success)
- [ ] TLS 1.3 handshake with wrong pinned key (failure)
- [ ] mTLS: server requires client certificate
- [ ] Session send/recv application data
- [ ] Session close (clean shutdown)
- [ ] Error handling for various failure modes
- [ ] Integration with bonnet.pyx

---

## Advantages Over iixp

1. **Standards Compliant**: RFC 7250, RFC 8446 (TLS 1.3)
2. **Interop**: Works with any TLS 1.3+ RPK client/server
3. **Security**: OpenSSL's battle-tested implementation
4. **Simpler**: No custom handshake state machine
5. **No PyNaCl**: One less dependency
6. **Future-proof**: OpenSSL maintains TLS implementation

---

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| OpenSSL < 3.2 on target system | Runtime version check with clear error |
| BIO pair complexity | Careful implementation, thorough testing |
| Different error handling | Wrap OpenSSL errors with context |
| Build system changes | Test on clean build environment |

---

## Timeline

1. Create `src/tls.pyx` with full implementation
2. Update `Makefile` for OpenSSL linking
3. Update `pyproject.toml` to remove PyNaCl
4. Update `src/bonnet.pyx` imports
5. Delete `src/iixp.pyx`
6. Build and test
7. Fix issues
8. Done

---

## References

- **RFC 7250**: Using Raw Public Keys in TLS/DTLS
- **RFC 8446**: TLS 1.3
- **RFC 8032**: Ed25519
- **RFC 7748**: X25519
- **OpenSSL 3.2 Release Notes**: RPK support announcement
