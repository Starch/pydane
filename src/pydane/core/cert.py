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

from hashlib import sha256, sha512

from Crypto.Util.asn1 import DerSequence
from OpenSSL.crypto import *


class Certificate(object):
    """A certificate fetched from a remote server."""
    def __init__(self, der):
        self.DER = der
        self.cert = load_certificate(FILETYPE_ASN1, der)

    @property
    def common_name(self):
        """Get the CommonName field of certificate subject."""
        return self.cert.get_subject().commonName

    def get_spki(self):
        """Get the Subject PublicKey info, DER encoded."""
        der = DerSequence()
        der.decode(self.DER)
        cert = DerSequence()
        cert.decode(der[0])
        return cert[6]

    def digest(self, algorithm):
        """Get an hash of the whole certificate, as bytestring.
        Supported algorithm are: sha256 and sha512."""
        if not algorithm:
            return self.DER
        if algorithm == 'sha256':
            return sha256(self.DER).digest()
        elif algorithm == 'sha512':
            return sha512(self.DER).digest()
        else:
            raise Exception('No algorithm ' + algorithm)

    def spki_digest(self, algorithm):
        """Get an hash of the SPKI, as bytestring.
        If algorithm is None, the public key is directly returned.
        Supported algorithm are: sha256 and sha512."""
        pkey_der = self.get_spki()
        if not algorithm:
            return pkey_der
        if algorithm == 'sha256':
            return sha256(pkey_der).digest()
        elif algorithm == 'sha512':
            return sha512(pkey_der).digest()
        else:
            raise Exception('No algorithm ' + algorithm)

    def as_str(self):
        return dump_certificate(FILETYPE_TEXT, self.cert).decode()

    def __str__(self):
        return '/' + '/'.join([(x + b'=' + y).decode()
                               for x, y in self.cert.get_subject().get_components()])
