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

from pydane.core.customssl import validate

import unittest


class CustomSSLTest(unittest.TestCase):

    def test_bad_cert(self):
        """Checks the customssl properly raise exceptions on bad data"""
        self.assertRaises(TypeError, validate, None)
        self.assertRaises(TypeError, validate, 1)
        self.assertRaises(RuntimeError, validate, b'123')

    def test_bad_extra_certs(self):
        """Checks proper exceptions when extra_certs is bad"""
        self.assertRaises(TypeError, validate, b'123', extra_certs=b'123')
        self.assertRaises(TypeError, validate, b'123', extra_certs=[1, 2, 3])
        self.assertRaises(RuntimeError, validate, b'123', extra_certs=[b'123'])


if __name__ == '__main__':
    unittest.main()
