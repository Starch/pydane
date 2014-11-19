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

""" Various protocol implementations.

This module contains some classes to fetch an SSL certificate on smtp, imap and
sieve servers.

A large part of this code is directly inspired from standard libraries stmplib
and imaplib.

"""

import logging
import socket

import pydane.core.ssl as ssl

TIMEOUT = 5.0  # 5 seconds timeout


class ProtoConnectionError(OSError):
    """Base class for all errors in this module."""
    pass


class Proto(object):
    """Base class for text-line protocols."""

    def __init__(self, hostname, port):
        self.host = hostname
        self.port = port

    def create_context(self):
        # In a perfect world, we could have use directly the ssl implementation
        # But we are not in a perfect world, and SSL is a PITA
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # we do not want the getpeercert to fail upon validation.
        return context

    def get_certificate(self):
        pass

    def __str__(self):
        return '{}({}:{})'.format(self.__class__.__name__, self.host, self.port)


class SSL(Proto):
    """This class should be used when using SSL (and not starttls).
    When the protocol is entirely wrapped within TLS/SSL, we just
    need to wraps the socket and fetch back the peer certificate.
    """
    protocol = ('https', 'imaps', 'pop3s')
    ports = (443, 993, 995)

    def get_certificate(self):
        context = self.create_context()

        with socket.create_connection((self.host, self.port), timeout=TIMEOUT) as sock:
            server_hostname = self.host if ssl.HAS_SNI else None
            with context.wrap_socket(sock, server_hostname=server_hostname) as sslsock:
                return sslsock.getpeercert(True), sslsock.getpeercertchain(True)


class SMTP(Proto):
    """SMTP STARTTLS protocol."""
    protocol = ('mx', 'submission')
    ports = (25, 587)

    def get_certificate(self):
        context = self.create_context()

        from smtplib import SMTP

        with SMTP(self.host, self.port, timeout=TIMEOUT) as smtp:
            smtp.starttls(context=context)
            return smtp.sock.getpeercert(True), smtp.sock.getpeercertchain(True)


class IMAP(Proto):
    """IMAP STARTTLS protocol."""
    protocol = ('imap', )
    ports = (143, )

    def get_certificate(self):
        context = self.create_context()

        from imaplib import IMAP4

        try:
            imap = IMAP4(host=self.host, port=self.port)
            imap.starttls(ssl_context=context)
            sock = imap.socket()
            return sock.getpeercert(True), sock.getpeercertchain(True)
        finally:
            try:
                imap.logout()
                imap.shutdown()
            except:
                pass


class SIEVE(Proto):
    """SIEVE STARTTLS protocol."""
    protocol = ('sieve', )
    ports = (2000, 4190)

    def get_certificate(self):
        context = self.create_context()

        with ManageSieve(self.host, self.port, timeout=TIMEOUT) as sieve:
            sieve.starttls(context=context)
            return sieve.sock.getpeercert(True), sieve.sock.getpeercertchain(True)


class SIEVEException(OSError):
    """Base class for all exceptions raised by ManageSieve class."""


class SIEVEConnectError(SIEVEException):
    """Could not connect to server."""


class SIEVEServerDisconnected(SIEVEException):
    """Not connected to any SIEVE server.

    This exception is raised when the server unexpectedly disconnects,
    or when an attempt is made to use the SIEVE instance before
    connecting it to a server.
    """


class SIEVEResponseException(SIEVEException):
    """Base class for all exceptions that include an SMTP error code.

    These exceptions are generated in some instances when the SMTP
    server returns an error code.  The error code is stored in the
    `smtp_code' attribute of the error, and the `smtp_error' attribute
    is set to the error message.
    """

    def __init__(self, msg):
        self.error = msg


_MAXLINE = 8192
_CRLF = '\r\n'


class ManageSieve(object):
    """
    There is no standard sieve libray in python, so this is a dumb implem that
    just goes to the STARTTLS call.
    It does not check capabilities.
    """
    OK = 'OK'
    NO = 'NO'
    BYE = 'BYE'

    def __init__(self, host='', port=0,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 source_address=None):
        self._host = host
        self.timeout = timeout
        self.source_address = source_address
        self._log = logging.getLogger(self.__class__.__qualname__)

        self.sock = None
        self.file = None
        self._tls_established = False

        if host:
            (code, msg) = self.connect(host, port)
            if code != self.OK:
                raise SIEVEConnectError(code, msg)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            code, message = self.docmd('LOGOUT')
            if code != self.OK:
                raise SIEVEResponseException(message)
        except SIEVEServerDisconnected:
            pass
        finally:
            self.close()

    def connect(self, host, port):
        self._log.debug('Connecting to %s:%s', host, port)
        self.sock = socket.create_connection((host, port), self.timeout, self.source_address)
        self.file = self.sock.makefile('rb')
        return self.getreply()

    def starttls(self, context=None):
        name = 'STARTTLS'
        if self._tls_established:
            raise SIEVEException('TLS session already established')
        # if name not in self.capabilities:
        # raise self.abort('TLS not supported by server')

        if context is None:
            context = ssl._create_stdlib_context()

        code, message = self.docmd(name)
        if code == self.OK:
            server_hostname = self._host if ssl.HAS_SNI else None
            self.sock = context.wrap_socket(self.sock,
                                            server_hostname=server_hostname)
            self.file = self.sock.makefile('rb')
            self._tls_established = True
            code, message = self.getreply()
        else:
            raise SIEVEException('Couldn\'t establish TLS session')

        return code, message

    def close(self):
        """Close the connection to the SIEVE server."""
        if self.file:
            self.file.close()
        self.file = None
        if self.sock:
            self.sock.close()
        self.sock = None

    def readline(self):
        try:
            line = self.file.readline(_MAXLINE + 1)
            if line:
                line = line.strip(b' \t\r\n')
            return line
        except OSError as e:
            self.close()
            raise SIEVEServerDisconnected('Connection unexpectedly closed: {}'.format(e))

    def docmd(self, cmd):
        self._log.debug('>> %s', cmd)
        self.sock.send((cmd + _CRLF).encode())
        return self.getreply()

    def getreply(self):
        resp = []
        typ = None

        while 1:
            line = self.readline()
            if not line:
                self.close()
                raise SIEVEServerDisconnected('Connection unexpectedly closed')

            line = line.decode()  # data should be encoded in UTF-8

            self._log.debug('<< %s', line)

            if len(line) > _MAXLINE:
                self.close()
                raise SIEVEResponseException('Line too long.')

            arr = line.split(' ')
            if arr[0] in (self.OK, self.NO, self.BYE):
                typ = arr[0]
                break
            else:
                resp.append(line)

        errmsg = '\n'.join(resp)

        return typ, errmsg


def get_protocol(name=None, port=None):
    import sys
    import inspect

    protos = inspect.getmembers(sys.modules[__name__],
                                lambda o: inspect.isclass(o) and issubclass(o, Proto))

    if name:
        for _, proto in protos:
            if hasattr(proto, 'protocol'):
                if name in proto.protocol:
                    return proto
        return None

    if port:
        for _, proto in protos:
            if hasattr(proto, 'ports'):
                if port in proto.ports:
                    return proto
        return None

    raise Exception('a port or a name should be given')
