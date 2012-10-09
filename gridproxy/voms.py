# -*- encoding: utf-8 -*-
#
# Copyright 2009-2012 Lev Shamardin.
#
# This file is part of gridproxy library.
#
# Gridproxy library is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# Gridpxoy library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with gridproxy library. If not, see <http://www.gnu.org/licenses/>.
#

"""Limited OO interface to libvomsc.so using ctypes"""

import ctypes
import datetime
import time
import types
from M2Crypto import X509

__all__ = ['VOMS', 'VOMSError']

# Known and supported names of VOMS shared library
dlnames = [
    # EPEL-packed on RHEL, or Fedora:
    'libvomsc.so.0', 'libvomsapi.so.1',
    # from Condor distribution on MacOSX:
    'libvomsapi_gcc64dbgpthr.0.dylib',
    # from VDT distribution on MacOSX:
    'libvomsapi_gcc32dbgpthr.0.dylib']

V = None
for dlname in dlnames:
    try:
        V = ctypes.CDLL(dlname)
        break
    except OSError:
        pass

if V is None:
    raise RuntimeError("Could not load libvomsc/libvomsapi shared library")

del dlnames
del dlname

class _voms(ctypes.Structure):
    _fields_ = [("siglen", ctypes.c_int32),
                ("signature", ctypes.c_char_p),
                ("user", ctypes.c_char_p),
                ("userca", ctypes.c_char_p),
                ("server", ctypes.c_char_p),
                ("serverca", ctypes.c_char_p),
                ("voname", ctypes.c_char_p),
                ("uri", ctypes.c_char_p),
                ("date1", ctypes.c_char_p),
                ("date2", ctypes.c_char_p),
                ("type", ctypes.c_int32),
                ("std", ctypes.c_void_p), # struct data **std
                ("custom", ctypes.c_char_p),
                ("datalen", ctypes.c_int32),
                ("version", ctypes.c_int32),
                ("fqan", ctypes.POINTER(ctypes.c_char_p)),
                ("serial", ctypes.c_char_p),
                ("ac", ctypes.c_void_p), # AC *ac
                ("holder", ctypes.c_void_p), # X509 *holder
                ]

class _vomsdata(ctypes.Structure):
    _fields_ = [("cdir", ctypes.c_char_p),
                ("vdir", ctypes.c_char_p),
                ("data", ctypes.POINTER(ctypes.POINTER(_voms))),
                ("workvo", ctypes.c_char_p),
                ("extra_data", ctypes.c_char_p),
                ("volen", ctypes.c_int32),
                ("extralen", ctypes.c_int32),
                ("real", ctypes.c_void_p), # struct vomsdata* real
                ]

_vomsdata_p = ctypes.POINTER(_vomsdata)

VOMS_Init = V.VOMS_Init
VOMS_Init.restype = _vomsdata_p
VOMS_Destroy = V.VOMS_Destroy
VOMS_RetrieveFromProxy = V.VOMS_RetrieveFromProxy
VOMS_Retrieve = V.VOMS_Retrieve

class VOMSError(RuntimeError):
    errors = {
        0: ('none', None),
        1: ('nosocket', 'Socket problem'),
        2: ('noident', 'Cannot identify itself (certificate problem)'),
        3: ('comm', 'Server problem'),
        4: ('param', 'Wrong parameters'),
        5: ('noext', 'VOMS extension missing'),
        6: ('noinit', 'Initialization error'),
        7: ('time', 'Error in time checking'),
        8: ('idcheck', 'User data in extension different from the real ones'),
        9: ('extrainfo', 'VO name and URI missing'),
        10: ('format', 'Wrong data format'),
        11: ('nodata', 'Empty extension'),
        12: ('parse', 'Parse error'),
        13: ('dir', 'Directory error'),
        14: ('sign', 'Signature error'),
        15: ('server', 'Unidentifiable VOMS server'),
        16: ('mem', 'Memory problems'),
        17: ('verify', 'Generic verification error'),
        18: ('type', 'Returned data of unknown type'),
        19: ('order', 'Ordering different than required'),
        20: ('servercode', 'Error from the server'),
        21: ('notavail', 'Method not available'),
        }

    def __init__(self, code):
        short, long = self.errors.get(code, ('oops', 'Unknown error %d' % code))
        RuntimeError.__init__(self, long)
        self.code = code
        self.name = short

class _utc(datetime.tzinfo):
    zero = datetime.timedelta(0)
    
    def utcoffset(self, dt):
        return self.zero

    def dst(self, dt):
        return self.zero

    def tzname(self, dt):
        return "UTC"

    def __repr__(self):
        return "<UTC>"

    def __str__(self):
        return "UTC"

utc = _utc()

def _translate_time(timestamp):
    t = time.strptime(timestamp, '%Y%m%d%H%M%SZ')
    return datetime.datetime(t[0], t[1], t[2], t[3], t[4], t[5], 0, utc)

class VOMS(object):
    recursion = {
        'chain': 0,
        'none': 1,
        'deep': 2
        }

    def __init__(self,
                 voms_dir="/etc/grid-security/vomsdir",
                 cert_dir="/etc/grid-security/certificates"):
        """
        Initialize VOMS library.
        
        Parameters:

        voms_dir: Path to directory with VOMS servers certificates info.
        cert_dir: Path to directory with CA certificates.
        """
        self.voms_dir = voms_dir
        self.cert_dir = cert_dir
        self.__vd = None
        self.__fqans = None

    def __flush(self):
        if self.__vd is not None:
            VOMS_Destroy(ctypes.byref(self.__vd))
            self.__vd = None
        self.__vd = VOMS_Init(self.voms_dir, self.cert_dir).contents
        self.__fqans = None
            
    def __del__(self):
        if self.__vd is not None:
            VOMS_Destroy(ctypes.byref(self.__vd))

    def from_proxy(self, recurse='chain'):
        """
        Retrieve and verify voms information from a proxy certificate
        of the calling user.

        recurse specifies the recursion type in check. Possible values:
        chain, none, deep
        """
        self.__flush()
        how = self.recursion[recurse]
        error = ctypes.c_int32(0)
        result = VOMS_RetrieveFromProxy(how, ctypes.byref(self.__vd), ctypes.byref(error))
        if result == 0:
            raise VOMSError(error.value)

    def from_x509_cert_chain(self, cert, chain, recurse='chain'):
        """
        Retrieve and verify voms information from a proxy certificate
        chain.

        Most probably you would like to use from_x509_stack function
        instead.
        """
        self.__flush()
        cert_ptr = ctypes.cast(long(cert._ptr()), ctypes.c_void_p)
        chain_ptr = ctypes.cast(long(chain._ptr()), ctypes.c_void_p)
        error = ctypes.c_int32(0)
        how = self.recursion[recurse]
        result = VOMS_Retrieve(cert_ptr, chain_ptr, how, ctypes.byref(self.__vd), ctypes.byref(error))
        if result == 0:
            raise VOMSError(error.value)

    def from_x509_stack(self, stack, recurse='chain'):
        """
        Retrieve and verify voms information from X509_Stack
        containing the whole proxy certificate chain.
        """
        self.from_x509_cert_chain(stack[0], stack)

    @property
    def _voms(self):
        return self.__vd.data.contents.contents

    @property
    def fqans(self):
        if self.__fqans is None:
            self.__fqans = []
            for fqan in iter(self._voms.fqan):
                if fqan is None:
                    break
                self.__fqans.append(fqan)
        return self.__fqans

    @property
    def custom_data(self):
        return ctypes.string_at(self._voms.custom, self._voms.datalen)

# The code below implements automatic attributes for the VOMS class as
# descriptors.
class _voms_prop(object):
    def __init__(self, aname, convfunc=lambda x: x):
        self.aname = aname
        self.convfunc = convfunc

    def __get__(self, object, type=None):
        return self.convfunc(getattr(object._voms, self.aname))

for attr in ('user', 'userca', 'server', 'serverca',
             ('vo', 'voname'),  'uri',
             ('not_before', 'date1', _translate_time),
             ('not_after', 'date2', _translate_time),
             'version', 'serial'):
    if type(attr) in types.StringTypes:
        setattr(VOMS, attr, _voms_prop(attr))
    else:
        setattr(VOMS, attr[0], _voms_prop(*attr[1:]))
