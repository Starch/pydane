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

# RFC 6698

import logging

from dns.resolver import Resolver, NXDOMAIN, NoNameservers
from dns import flags
from dns import rdatatype

PKIX_TA, PKIX_EE, DANE_TA, DANE_EE = range(4)
CERT, SPKI = range(2)
FULL, SHA256, SHA512 = range(3)
ERROR, UNTRUSTED, INSECURE, TRUSTED, NO_RECORD, NO_MATCH = range(6)

log = logging.getLogger('pydane.core.tlsa')


class TLSAValidator(object):
    """Checks a certificate against some associated TLSA records."""
    ALGO = {FULL: None, SHA256: 'sha256', SHA512: 'sha512'}

    def __init__(self, records, secure=False):
        self.records = records
        self.secure = secure

    def get_algo(self, record):
        try:
            return self.ALGO[record.mtype]
        except KeyError:
            raise KeyError('Unknown algorithm ' + record.mtype)

    def _check_record(self, cert, record):
        algorithm = self.get_algo(record)

        if record.selector == CERT:
            cert_data = cert.digest(algorithm)
        elif record.selector == SPKI:
            cert_data = cert.spki_digest(algorithm)
        else:
            raise Exception('Selector {} not yet managed.', record.selector)

        return cert_data == record.cert

    def validate(self, cert):
        """Validates the given certificate against the one or many
        TLSA records fetched for it."""
        result = UNTRUSTED

        for record in self.records:
            log.debug('Checking cert against %s', record)
            if record.usage == DANE_EE:
                if self._check_record(cert, record):
                    result = self.secure and TRUSTED or INSECURE  # FIXME dangerous and/or line
                    break  # sufficient

            else:
                log.debug('TLSA usage={} is not supported yet.', record.usage)

        return result


def get_records(host, port, proto='tcp'):
    resolver = Resolver()
    resolver.set_flags(flags.AD + flags.RD)

    name = '_{}._{}.{}'.format(port, proto, host)

    try:
        rrset = resolver.query(name, rdtype=rdatatype.TLSA)
    except NXDOMAIN:
        log.debug('No record found for %s', name)
        raise
    except NoNameservers:
        log.debug('No unbroken server for resolving %s', name)
        # It may be because there is a bad dnssec key
        resolver.set_flags(flags.CD + flags.RD)
        rrset = resolver.query(name, rdtype=rdatatype.TLSA)
        log.debug('Without validation we have an answer: %s', rrset)

    for record in rrset:
        log.debug(record)

    secure = rrset.response.flags & flags.AD == flags.AD

    if not secure:
        log.warn('Not DNSSEC signed!')

    return TLSAValidator([r for r in rrset], secure)
