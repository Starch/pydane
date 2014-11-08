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


Caveats
-------

 * Works only works for TLSA usage 3 because does not do any PKIX validation,
 * use default resolver, that may be not DNSSEC enabled, should use libunbound instead,
 * ports/protocols are hardcoded,
 * SSHFP not supported.

