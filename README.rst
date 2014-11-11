.. coding: utf-8

pydane: tool for checking dane records
======================================

pydane is a simple tool for checking server certificates against their
potential DANE/TLSA records in DNS. There are numerous tools here and
there, but most of them do not handle well the STARTTLS servers out
there.

The aim of this tool is to quickly validate a TLSA record was properly
created in DNS for the given service.

Usage
-----

.. code-block::

    tlsa_check [options] hostname [port]


By default, `tlsa_check` checks an https server against the potential
TLSA record.

Examples
--------

* Certificate and record matches, and record was obtained from a signed zone

.. code-block::

    % tlsa_check www.debian.org
    Matching TLSA secure record for www.debian.org:443

* Certificate and record matches, and record was not obtained from a signed zone

.. code-block::

    % tlsa_check laquadrature.net
    Not DNSSEC signed!
    Matching TLSA insecure record for laquadrature.net:443

* No TLSA record was found

.. code-block::

    % tlsa_check imap.gmail.com 993
    No TLSA record for IMAP(imap.gmail.com:993):


Caveats
-------

 * Works only works for TLSA usage 3 because does not do any PKIX validation,
 * use default resolver, that may be not DNSSEC enabled, should use libunbound instead,
 * ports/protocols are hardcoded,
 * SSHFP not supported.

