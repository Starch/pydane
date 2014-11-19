# coding=utf-8

# Copyright (C) 2014, Alexandre Vaissière
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""Implementation of ssl.SSLSocket and ssl.SSLContext like objects
using openssl. The aim is to be able to fetch the peer chain of
certificate, feature that official ssl module will support only in
3.5.
"""

from OpenSSL import SSL
from OpenSSL.crypto import *

from ssl import _ASN1Object, _RESTRICTED_SERVER_CIPHERS
from ssl import Purpose

HAS_SNI = True
"""PyOpenSSL supports SNI."""

CERT_NONE = SSL.VERIFY_NONE
CERT_REQUIRED = SSL.VERIFY_PEER
CERT_OPTIONAL = SSL.VERIFY_CLIENT_ONCE


def create_default_context(purpose=Purpose.SERVER_AUTH, *, cafile=None,
                           capath=None, cadata=None):
    """Create a SSLContext object with default settings.

    NOTE: The protocol and settings may change anytime without prior
          deprecation. The values represent a fair balance between maximum
          compatibility and security.
    """
    if not isinstance(purpose, _ASN1Object):
        raise TypeError(purpose)

    context = PyOpenSSLContext(SSL.SSLv23_METHOD)

    # SSLv2 considered harmful.
    context.options |= SSL.OP_NO_SSLv2

    # SSLv3 has problematic security and is only required for really old
    # clients such as IE6 on Windows XP
    context.options |= SSL.OP_NO_SSLv3

    # disable compression to prevent CRIME attacks (OpenSSL 1.0+)
    context.options |= SSL.OP_NO_COMPRESSION

    if purpose == Purpose.SERVER_AUTH:
        # verify certs and host name in client mode
        context.verify_mode = SSL.VERIFY_PEER
        # ssl.CERT_REQUIRED
        context.check_hostname = True
    elif purpose == Purpose.CLIENT_AUTH:
        # Prefer the server's ciphers by default so that we get stronger
        # encryption
        context.options |= SSL.OP_CIPHER_SERVER_PREFERENCE

        # Use single use keys in order to improve forward secrecy
        context.options |= SSL.OP_SINGLE_DH_USE
        context.options |= getattr(SSL, 'OP_SINGLE_ECDH_USE', 0)

        # disallow ciphers with known vulnerabilities
        context.set_ciphers(_RESTRICTED_SERVER_CIPHERS)

    if cafile or capath or cadata:
        context.load_verify_locations(cafile, capath, cadata)
    elif context.verify_mode != SSL.VERIFY_NONE:
        # no explicit cafile, capath or cadata but the verify mode is
        # CERT_OPTIONAL or CERT_REQUIRED. Let's try to load default system
        # root CA certificates for the given purpose. This may fail silently.
        context.load_default_certs(purpose)
    return context


def _create_stdlib_context():
    return create_default_context()


class PyOpenSSLSocket(object):
    def __init__(self, sock, context, server_hostname=None):
        self.con = SSL.Connection(context, sock)
        self.closed = False
        if server_hostname:
            self.con.set_tlsext_host_name(server_hostname.encode())

        self.con.set_connect_state()
        self._do_handshake()

    def _do_handshake(self):
        while True:  # FIXME dangerous
            try:
                self.con.do_handshake()
                break
            except (SSL.WantWriteError, SSL.WantReadError):
                pass

    def recv_into(self, buffer, bufsize=0, flags=0):
        if not bufsize:
            bufsize = len(buffer)

        buf = None
        while True:
            try:
                buf = self.con.recv(bufsize, flags=flags)
                break
            except (SSL.WantReadError, SSL.WantWriteError):
                pass
            except SSL.ZeroReturnError:
                break

        if not buf:
            return 0
        # FIXME there must be a better way than this.
        for i, v in enumerate(buf):
            buffer[i] = v
        return len(buf)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _decref_socketios(self):
        pass

    def recv(self, bufsize, flags=None):
        length = 0
        buf = []
        while not length:
            try:
                buf = self.con.recv(bufsize, flags=flags)
            except (SSL.WantReadError, SSL.WantWriteError, SSL.WantX509LookupError):
                length = 0
            except SSL.ZeroReturnError:
                return []
            else:
                length = len(buf)
        return buf
    read = recv

    def send(self, buf, flags=0):
        try:
            return self.con.send(buf, flags=flags)
        except (SSL.WantReadError, SSL.WantWriteError):
            return 0
    write = send

    def sendall(self, buf, flags=0):
        left_to_send = len(buf)
        total_sent = 0

        while left_to_send:
            try:
                written = self.con.send(buf, flags=flags)
            except (SSL.WantReadError, SSL.WantWriteError):
                pass
            else:
                left_to_send -= written
                total_sent += written
                buf = buf[total_sent:]

    def close(self):
        self.con.close()
        self.closed = True

    def readable(self):
        return True

    def flush(self):
        pass

    def makefile(self, mode, bufsize=-1):
        from socket import SocketIO
        import io
        raw = SocketIO(self, mode)
        return io.BufferedReader(raw)

    def getpeercert(self, binary_form=False):
        x509 = self.con.get_peer_certificate()
        if not x509:
            return None
        if binary_form:
            return dump_certificate(FILETYPE_ASN1, x509)
        return {}

    def getpeercertchain(self, binary_form=False):
        x509s = self.con.get_peer_cert_chain()
        if not x509s:
            return []
        if binary_form:
            return [dump_certificate(FILETYPE_ASN1, x509) for x509 in x509s]
        return [{} for _ in x509s]


class PyOpenSSLContext(object):
    def __init__(self, method=SSL.SSLv23_METHOD):
        self.ctx = SSL.Context(method)
        self.method = method
        self.options = 0
        self.verify_mode = None
        self.check_hostname = False
        self.ciphers = None
        self.cafile = None
        self.capath = None

    def set_ciphers(self, ciphers):
        self.ciphers = ciphers

    def load_verify_locations(self, cafile, capath, cadata):
        self.cafile = cafile
        self.capath = capath

    def wrap_socket(self, sock, server_side=False,
                    do_handshake_on_connect=True,
                    suppress_ragged_eofs=True,
                    server_hostname=None):
        ctx = SSL.Context(self.method)
        ctx.set_verify(self.verify_mode, self)
        ctx.set_options(self.options)
        if self.ciphers:
            ctx.set_cipher_list(self.ciphers)
        if self.cafile or self.capath:
            ctx.load_verify_locations(self.cafile, self.capath)

        return PyOpenSSLSocket(sock, ctx, server_hostname=server_hostname)

    def load_default_certs(self, purpose):
        pass

    def __call__(self, *args, **kwargs):
        return True


