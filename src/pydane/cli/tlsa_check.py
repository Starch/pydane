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
from pydane.core.proto import KNOWN_PROTOCOLS

log = logging.getLogger('tlsa_check')


def check(proto):
    try:
        validator = tlsa.get_records(proto.host, proto.port)
    except Exception as e:
        print('No TLSA record for {}: {}'.format(proto, e))
        sys.exit(1)

    try:
        cert = Certificate(proto.get_certificate())
    except Exception as e:
        print('Unable to get certificate from {}: {}'.format(proto, e))
        sys.exit(1)

    log.debug('Peer certificate:\n%s', cert.as_str())

    if validator.validate(cert) == tlsa.TRUSTED:
        print('Matching TLSA secure record for {}:{}'.format(proto.host, proto.port))
        sys.exit(0)
    elif validator.validate(cert) == tlsa.INSECURE:
        print('Matching TLSA insecure record for {}:{}'.format(proto.host, proto.port))
        sys.exit(2)
    else:
        print('No correct TLSA record for {}:{}'.format(proto.host, proto.port))
        sys.exit(3)


def tlsa_check():
    parser = ArgumentParser(description='Checks server certificates against TLSA records')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('hostname', type=str)
    parser.add_argument('port', type=int, default=443, nargs='?')

    arguments = parser.parse_args(sys.argv[1:])

    if arguments.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)-15s [%(levelname)s] %(message)s')

    # FIXME we should try here to resolve hostname first with AD flag, then with CD
    # FIXME in order to work even if DNSSEC validation of host fails.
    if arguments.port in KNOWN_PROTOCOLS:
        proto = KNOWN_PROTOCOLS[arguments.port](arguments.hostname, arguments.port)
    else:
        raise Exception('Protocol not yet managed: {}'.format(arguments.port))

    check(proto)


if __name__ == '__main__':
    tlsa_check()
