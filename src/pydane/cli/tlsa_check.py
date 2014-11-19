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
import sys
from argparse import ArgumentParser

from pydane.core import tlsa
from pydane.core.cert import Certificate
from pydane.core.proto import get_protocol

log = logging.getLogger('tlsa_check')

TRUSTED, INSECURE, UNTRUSTED = range(3)


class ScriptError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status


def check(proto):
    try:
        validator = tlsa.get_records(proto.host, proto.port)
    except Exception as e:
        return UNTRUSTED, 'No TLSA record for {}'.format(proto)

    try:
        cert, chain = proto.get_certificate()
    except Exception as e:
        return UNTRUSTED, 'Unable to get certificate from {}: {}'.format(proto, e)

    if cert:
        cert = Certificate(cert)
    else:
        raise ScriptError(1, 'Unable to get certificate from {}: {}'.format(proto, 'certificate is None'))

    if chain:
        chain = [Certificate(x) for x in chain]
    else:
        raise ScriptError(1, 'Unable to get chain from {}: {}'.format(proto, 'chain is None'))

    result = validator.validate(cert)

    if result == tlsa.TRUSTED:
        return TRUSTED, 'Matching TLSA secure record for {}:{}'.format(proto.host, proto.port)
    elif result == tlsa.INSECURE:
        return INSECURE, 'Matching TLSA insecure record for {}:{}'.format(proto.host, proto.port)
    else:
        return UNTRUSTED, 'No correct TLSA record for {}:{}'.format(proto.host, proto.port)


def tlsa_check():
    parser = ArgumentParser(description='Checks server certificates against TLSA records')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('hostname', type=str)
    parser.add_argument('port', type=int, default=443, nargs='?')

    arguments = parser.parse_args(sys.argv[1:])

    if arguments.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)-15s [%(levelname)s] %(message)s')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)-15s [%(levelname)s] %(message)s')

    # FIXME we should try here to resolve hostname first with AD flag, then with CD
    # FIXME in order to work even if DNSSEC validation of host fails.
    protocol = get_protocol(port=arguments.port)
    if protocol:
        proto = protocol(arguments.hostname, arguments.port)
    else:
        raise Exception('Protocol not yet managed: {}'.format(arguments.port))

    status = -1
    try:
        status, m = check(proto)
        if status == 0:
            log.info(m)
        else:
            log.warn(m)
    except ScriptError as se:
        print(se)
        sys.exit(se.status)
    else:
        sys.exit(status)


if __name__ == '__main__':
    tlsa_check()
