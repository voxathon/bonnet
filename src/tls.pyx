# cython: language_level=3

import socket
import os
from cpython.bytes cimport PyBytes_FromStringAndSize
from libc.string cimport memcpy

class TLSError(OSError):
    def __init__(self, message, ssl_error=0, openssl_error=""):
        super().__init__(message)
        self.ssl_error = ssl_error
        self.openssl_error = openssl_error

class HandshakeError(TLSError):
    pass

class PeerVerificationError(TLSError):
    pass

cdef extern from "openssl/ssl.h":
    unsigned long OpenSSL_version_num()
    const char *OpenSSL_version(int type)
    int OPENSSL_VERSION

    ctypedef struct SSL_CTX
    ctypedef struct SSL_METHOD
    ctypedef struct SSL
    ctypedef struct BIO
    ctypedef struct EVP_PKEY
    ctypedef struct OSSL_LIB_CTX
    ctypedef struct OSSL_PARAM

    SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
    const SSL_METHOD *TLS_server_method()
    const SSL_METHOD *TLS_client_method()
    void SSL_CTX_free(SSL_CTX *ctx)

    int SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version)
    int SSL_CTX_set1_server_cert_type(SSL_CTX *ctx, const unsigned char *val, size_t len)
    int SSL_CTX_set1_client_cert_type(SSL_CTX *ctx, const unsigned char *val, size_t len)

    int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)

    int TLS1_3_VERSION

    SSL *SSL_new(SSL_CTX *ctx)
    void SSL_free(SSL *ssl)
    void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio)

    int SSL_do_handshake(SSL *ssl)
    int SSL_is_init_finished(SSL *ssl)
    int SSL_get_error(SSL *ssl, int ret)

    int SSL_ERROR_NONE
    int SSL_ERROR_ZERO_RETURN
    int SSL_ERROR_WANT_READ
    int SSL_ERROR_WANT_WRITE
    int SSL_ERROR_SSL
    
    int SSL_read(SSL *ssl, void *buf, int num)
    int SSL_write(SSL *ssl, const void *buf, int num)
    int SSL_pending(const SSL *ssl)

    int SSL_set_verify(SSL *ssl, int mode, void *callback)
    int SSL_VERIFY_PEER
    int SSL_VERIFY_FAIL_IF_NO_PEER_CERT

    int SSL_add_expected_rpk(SSL *ssl, EVP_PKEY *rpk)
    int SSL_get_verify_result(SSL *ssl)
    int X509_V_OK
    int X509_V_ERR_RPK_UNTRUSTED

    EVP_PKEY *SSL_get0_peer_rpk(const SSL *ssl)

cdef extern from "openssl/bio.h":
    int BIO_new_bio_pair(BIO **bio1, size_t writebuf1, BIO **bio2, size_t writebuf2)
    int BIO_read(BIO *b, void *buf, int len)
    int BIO_write(BIO *b, const void *buf, int len)
    size_t BIO_ctrl_pending(BIO *b)
    void BIO_free_all(BIO *a)
    void BIO_free(BIO *a)

cdef extern from "openssl/evp.h":
    # OpenSSL 3.x uses int type for old functions, but has EVP_PKEY_new_raw_private_key. Let's define it properly.
    EVP_PKEY *EVP_PKEY_new_raw_private_key(
        int type,
        void *engine,
        const unsigned char *key,
        size_t keylen
    )
    EVP_PKEY *EVP_PKEY_new_raw_public_key(
        int type,
        void *engine,
        const unsigned char *key,
        size_t keylen
    )
    int EVP_PKEY_ED25519
    int EVP_PKEY_get_raw_public_key(EVP_PKEY *pkey, unsigned char *pub, size_t *len)
    int EVP_PKEY_get_raw_private_key(EVP_PKEY *pkey, unsigned char *priv, size_t *len)
    EVP_PKEY *EVP_PKEY_Q_keygen(OSSL_LIB_CTX *libctx, const OSSL_PARAM *propq, const char *type, ...)
    void EVP_PKEY_free(EVP_PKEY *pkey)

cdef extern from "openssl/err.h":
    unsigned long ERR_get_error()
    void ERR_error_string_n(unsigned long e, char *buf, size_t len)

cdef str _get_openssl_error():
    cdef unsigned long err = ERR_get_error()
    cdef char buf[256]
    ERR_error_string_n(err, buf, sizeof(buf))
    return buf.decode('utf-8', 'replace')

cdef void _check_openssl_version() except *:
    cdef unsigned long version = OpenSSL_version_num()
    # OpenSSL 3.2.0 = 0x30200000L
    if version < 0x30200000:
        raise RuntimeError(
            f"OpenSSL 3.2+ required for RPK support. "
            f"Found: {OpenSSL_version(OPENSSL_VERSION).decode('utf-8', 'replace')}"
        )

# Ensure checking at import time
_check_openssl_version()

# TLSEXT_cert_type_rpk value
cdef int TLSEXT_cert_type_rpk = 0x1000

cdef SSL_CTX *_create_context(bint is_server) except NULL:
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

cdef void _setup_bio_pair(SSL *ssl, BIO **net_bio_out) except *:
    cdef BIO *ssl_bio = NULL
    cdef BIO *net_bio = NULL
    
    if BIO_new_bio_pair(&ssl_bio, 0, &net_bio, 8192) != 1:
        raise MemoryError("Failed to create BIO pair")
    
    SSL_set_bio(ssl, ssl_bio, ssl_bio)
    net_bio_out[0] = net_bio


cdef class Identity:
    cdef EVP_PKEY *_pkey
    cdef unsigned char _public_key[32]
    
    def __cinit__(self):
        self._pkey = NULL
    
    def __dealloc__(self):
        if self._pkey:
            EVP_PKEY_free(self._pkey)

    @staticmethod
    def generate():
        cdef Identity ident = Identity()
        ident._pkey = EVP_PKEY_Q_keygen(NULL, NULL, b"ED25519")
        if not ident._pkey:
            raise TLSError("Failed to generate Ed25519 key", 0, _get_openssl_error())
        
        cdef size_t publen = 32
        EVP_PKEY_get_raw_public_key(ident._pkey, ident._public_key, &publen)
        return ident

    @staticmethod
    def from_private_key(bytes key not None):
        if len(key) != 32:
            raise ValueError("Ed25519 private key must be 32 bytes")
        
        cdef Identity ident = Identity()
        ident._pkey = EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519,
            NULL,
            <const unsigned char*>key,
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

    @property
    def private_key(self):
        cdef unsigned char priv[32]
        cdef size_t privlen = 32
        if EVP_PKEY_get_raw_private_key(self._pkey, priv, &privlen) != 1:
            raise TLSError("Failed to get private key", 0, _get_openssl_error())
        return bytes(priv[:32])

cdef class Session:
    cdef SSL *_ssl
    cdef BIO *_net_bio
    cdef object _sock
    cdef bytes _peer_identity
    
    def __cinit__(self):
        self._ssl = NULL
        self._net_bio = NULL
    
    def __init__(self, ssl_ptr, net_bio_ptr, sock, peer_id):
        # We need to pass raw pointers, so we use a hack to pass them as integers
        # or we just bypass __init__ and set them in a factory function.
        # But let's assume we can set them in a factory function instead.
        pass

    def __dealloc__(self):
        if self._ssl:
            SSL_free(self._ssl)
        if self._net_bio:
            BIO_free_all(self._net_bio)

    cpdef bytes recv(self):
        # Pump incoming data from socket to BIO
        cdef char net_buf[8192]
        cdef int net_len
        cdef int buflen
        
        while True:
            # Check if SSL has data ready
            buflen = SSL_pending(self._ssl)
            if buflen > 0:
                break
            
            # Check if BIO has pending data
            if BIO_ctrl_pending(self._net_bio) > 0:
                break
            
            # Need more data from socket
            try:
                net_len = self._sock.recv_into(net_buf, 8192)
            except BlockingIOError:
                return b""
            if net_len <= 0:
                return b""  # Connection closed
            BIO_write(self._net_bio, net_buf, net_len)
        
        # Read decrypted data
        cdef char app_buf[16384]
        cdef int app_len = SSL_read(self._ssl, app_buf, 16384)
        cdef int err
        
        if app_len <= 0:
            err = SSL_get_error(self._ssl, app_len)
            if err == SSL_ERROR_ZERO_RETURN:
                return b""  # Clean shutdown
            if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE:
                return b""
            raise TLSError("SSL_read failed", err, _get_openssl_error())
        
        return PyBytes_FromStringAndSize(app_buf, app_len)

    cpdef void send(self, bytes data) except *:
        cdef int ret = SSL_write(self._ssl, <const char*>data, len(data))
        if ret <= 0:
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

    def close(self, int code=0, str reason=""):
        # Not fully implementing close notify for simplicity, but could SSL_shutdown
        try:
            self._sock.close()
        except:
            pass

    @property
    def peer_identity(self) -> bytes:
        return self._peer_identity
    
    @property
    def client_identity(self) -> bytes:
        return self._peer_identity

cdef Session _create_session(SSL *ssl, BIO *net_bio, object sock, bytes peer_identity):
    cdef Session s = Session()
    s._ssl = ssl
    s._net_bio = net_bio
    s._sock = sock
    s._peer_identity = peer_identity
    return s


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
        if ret <= 0:
            err = SSL_get_error(ssl, ret)
            
            if err == SSL_ERROR_WANT_READ:
                # Need data from network
                try:
                    buflen = sock.recv_into(buf, 8192)
                except BlockingIOError:
                    # In a real async framework we'd yield here
                    continue
                if buflen <= 0:
                    raise HandshakeError("Connection closed during handshake")
                BIO_write(net_bio, buf, buflen)
                
            elif err == SSL_ERROR_WANT_WRITE:
                pass # Handled below
                
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
        
        # Always pump outgoing data
        buflen = BIO_ctrl_pending(net_bio)
        if buflen > 0:
            buflen = BIO_read(net_bio, buf, buflen)
            if buflen > 0:
                sock.sendall(PyBytes_FromStringAndSize(buf, buflen))

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
    
    return _create_session(ssl, net_bio, sock, bytes(peer_pub[:32]))

def connect(
    object sock,
    Identity client_identity,
    bytes server_pinned = None
):
    cdef SSL_CTX *ctx = NULL
    cdef SSL *ssl = NULL
    cdef BIO *net_bio = NULL
    cdef EVP_PKEY *pinned_pkey = NULL

    try:
        ctx = _create_context(False)
        if SSL_CTX_use_PrivateKey(ctx, client_identity._pkey) != 1:
            raise TLSError("Failed to set client private key", 0, _get_openssl_error())

        ssl = SSL_new(ctx)
        if not ssl:
            raise MemoryError("Failed to create SSL object")
        
        _setup_bio_pair(ssl, &net_bio)

        if server_pinned:
            if len(server_pinned) != 32:
                raise ValueError("Pinned server key must be 32 bytes")
            pinned_pkey = EVP_PKEY_new_raw_public_key(
                EVP_PKEY_ED25519, NULL, <const unsigned char*>server_pinned, 32
            )
            if not pinned_pkey:
                raise TLSError("Failed to load pinned server key", 0, _get_openssl_error())
            
            SSL_add_expected_rpk(ssl, pinned_pkey)
            SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL)
        
        session = _do_handshake(ssl, net_bio, sock, False, server_pinned)
        
        # _do_handshake consumed ssl and net_bio if successful
        ssl = NULL
        net_bio = NULL
        return session

    finally:
        if pinned_pkey:
            EVP_PKEY_free(pinned_pkey)
        if ctx:
            SSL_CTX_free(ctx)
        if ssl:
            SSL_free(ssl)
        if net_bio:
            BIO_free_all(net_bio)

def accept(
    object sock,
    Identity server_identity,
    bytes client_pinned = None
):
    cdef SSL_CTX *ctx = NULL
    cdef SSL *ssl = NULL
    cdef BIO *net_bio = NULL
    cdef EVP_PKEY *pinned_pkey = NULL

    try:
        ctx = _create_context(True)
        if SSL_CTX_use_PrivateKey(ctx, server_identity._pkey) != 1:
            raise TLSError("Failed to set server private key", 0, _get_openssl_error())

        ssl = SSL_new(ctx)
        if not ssl:
            raise MemoryError("Failed to create SSL object")
        
        _setup_bio_pair(ssl, &net_bio)

        # Server always requires client auth (mTLS)
        SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL)

        if client_pinned:
            if len(client_pinned) != 32:
                raise ValueError("Pinned client key must be 32 bytes")
            pinned_pkey = EVP_PKEY_new_raw_public_key(
                EVP_PKEY_ED25519, NULL, <const unsigned char*>client_pinned, 32
            )
            if not pinned_pkey:
                raise TLSError("Failed to load pinned client key", 0, _get_openssl_error())
            
            SSL_add_expected_rpk(ssl, pinned_pkey)
        
        session = _do_handshake(ssl, net_bio, sock, True, client_pinned)
        
        # _do_handshake consumed ssl and net_bio if successful
        ssl = NULL
        net_bio = NULL
        return session

    finally:
        if pinned_pkey:
            EVP_PKEY_free(pinned_pkey)
        if ctx:
            SSL_CTX_free(ctx)
        if ssl:
            SSL_free(ssl)
        if net_bio:
            BIO_free_all(net_bio)

