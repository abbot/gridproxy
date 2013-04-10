# -*- encoding: utf-8 -*-
#
# Copyright 2009-2013 Lev Shamardin.
#
# This file is part of gridproxy library.
#
# Gridproxy library is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# Gridproxy library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with gridproxy library. If not, see <http://www.gnu.org/licenses/>.
#

from M2Crypto import X509, m2

def x509_load_chain_der(buffer):
    """Load an X509_Stack of certificates from a DER-formatted dump"""
    return X509.X509_Stack(m2.make_stack_from_der_sequence(str(buffer)), _pyfree=1)
