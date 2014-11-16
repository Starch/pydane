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

import logging
from itertools import chain

from dns.resolver import Resolver, NoNameservers, NXDOMAIN
from dns import flags
from dns import rdatatype as rdt

log = logging.getLogger('pydane.core.dns')


class CustomResolver(object):
    def __init__(self):
        self.resolver = Resolver()
        self.resolver.use_edns(0, 0, 4096)
        self.resolver.set_flags(flags.AD + flags.RD)

        self.degraded = Resolver()
        self.degraded.use_edns(0, 0, 4096)
        self.degraded.set_flags(flags.CD + flags.RD)

    def query(self, fqdn, rdatatype=rdt.A, degraded=False):
        log.debug('Query %s %s', fqdn, rdatatype)
        try:
            return self.resolver.query(fqdn, rdatatype)
        except NoNameservers:
            if degraded:
                return self.degraded.query(fqdn, rdatatype)
            raise
        except NXDOMAIN:
            if degraded:
                return self.degraded.query(fqdn, rdatatype)
            return None

    def srv(self, name, domainname, proto='tcp'):
        fqdn = '_{}._{}.{}'.format(name, proto, domainname)
        return self.query(fqdn, rdt.SRV)

    def tlsa(self, hostname, port, proto='tcp'):
        fqdn = '_{}._{}.{}'.format(port, proto, hostname)
        return self.query(fqdn, rdt.TLSA)

    def mx(self, domainname):
        return self.query(domainname, rdt.MX)


RESOLVER = CustomResolver()


class Domain(object):
    def __init__(self, domainname):
        self.domainname = domainname

    def services(self):
        """"""
        return chain(self.mx(),
                     self.imap(),
                     self.pop(),
                     self.submission(),
                     self.sieve(),
                     self.xmpp_client(),
                     self.xmpp_server())

    def mx(self):
        """Iterable over ('mx', preference, 0, 25, exchange)"""
        rrset = RESOLVER.mx(self.domainname)
        if rrset:
            for r in rrset:
                yield ('mx', r.preference, 0, 25, r.exchange.to_text(True))

    def imap(self):
        return chain(self.service('imap'),
                     self.service('imaps'))

    def pop(self):
        return chain(self.service('pop3'),
                     self.service('pop3s'))

    def sieve(self):
        return self.service('sieve')

    def submission(self):
        return self.service('submission')

    def xmpp_client(self):
        return self.service('xmpp-client')

    def xmpp_server(self):
        return self.service('xmpp-server')

    def service(self, name, proto='tcp'):
        rrset = RESOLVER.srv(name, self.domainname, proto=proto)
        if rrset:
            for r in rrset:
                host = r.target.to_text(True)
                if host != '.':
                    yield (name, r.priority, r.weight, r.port, host)

    def __str__(self):
        return 'Domain({})'.format(self.domainname)

