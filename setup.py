#!/usr/bin/env python
# -*- encoding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
    
setup(name="gridproxy",
      version="0.2",
      description="Small library for working with grid proxy certificates and VOMS extensions",
      long_description="""\
Small library for working with grid proxy certificates and VOMS \
extensions. VOMS support is implemented as a ctypes wrapper for \
regular voms libraries. \
""",
      classifiers=['Development Status :: 4 - Beta',
                   'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
                   'Operating System :: POSIX :: Linux',
                   'Operating System :: MacOS :: MacOS X',
                   'Programming Language :: Python',
                   'Topic :: Internet',
                   'Topic :: Security :: Cryptography',
                   'Topic :: Software Development :: Libraries :: Python Modules'],
      keywords=['voms', 'proxy', 'certificate', 'x509', 'grid'],
      author="Lev Shamardin",
      author_email="shamardin@gmail.com",
      url="https://github.com/abbot/gridproxy",
      license="GPLv3+",
      packages=['gridproxy'],
      zip_safe=True,
      )
