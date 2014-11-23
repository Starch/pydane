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

from setuptools import setup, find_packages, Extension

customssl = Extension('pydane.core.customssl',
                      define_macros=[('MAJOR_VERSION', '1'),
                                     ('MINOR_VERSION', '0')],
                      include_dirs=['/usr/local/include'],
                      libraries=['crypto', 'ssl'],
                      library_dirs=['/usr/local/lib'],
                      sources=['c/pydane/core/customssl.c'])

setup(
    name='pydane',
    version='0.1.0',
    description='Tool for checking DANE/TLSA records',
    # long_description=long_description,
    url='https://github.com/Starch/pydane',
    license='ISC',

    author='Alexandre Vaissière',
    author_email='avaiss@fmiw.org',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: System Administrators',
        'Topic :: Internet :: Name Service (DNS)',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
    ],

    keywords='dnssec dane tlsa pkix ssl',

    packages=find_packages(),
    package_dir={'': 'src', 'tests': '.'},
    test_suite='tests',

    ext_modules=[customssl],

    install_requires=['dnspython3', 'pyopenssl', 'pycrypto'],

    entry_points={
        'console_scripts': [
            'tlsa_check=pydane.cli.tlsa_check:tlsa_check',
        ],
    },
)