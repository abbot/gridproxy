#!/usr/bin/env python
# -*- encoding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup
    
setup(name="gridproxy",
      version="0.1",
      description="Small library for working with grid proxy certificates and VOMS extensions",
      author="Lev Shamardin",
      author_email="shamardin@gmail.com",
      license="GPLv3+",
      packages=['gridproxy']
      )
