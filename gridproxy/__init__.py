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

"""Grid proxy certificate functions."""

import os
import re
import struct
import tempfile
import time
from M2Crypto import X509, EVP, RSA, ASN1, m2, BIO

CLOCK_SKEW = 5*60

def get_proxy_filename():  
    """
    Return a proxy certificate filename for the calling user.
    """
    if 'X509_USER_PROXY' in os.environ:
        return os.environ['X509_USER_PROXY']

    if os.name == 'posix':
        filename = 'x509up_u%d' % os.getuid()
    else:
        raise RuntimeError("X509_USER_PROXY must be set for %s platform. Can't determine proxy file location." % os.name)

    if os.uname()[0] == 'Darwin':
        proxydir = '/tmp'
    else:
        proxydir = tempfile.gettempdir()

    return os.path.join(proxydir, filename)

def generate_keypair(bits=512, exponent=65537):
    """Generate a new RSA key pair. Returns a tuple of (RSA, PKey)"""
    rsa = RSA.gen_key(bits, exponent, lambda x: None)
    pkey = EVP.PKey()
    pkey.assign_rsa(rsa)
    return rsa, pkey

# pylint: disable-msg=R0914,R0915,R0912
def generate_proxycert(new_pkey, cert, key, **kwargs):
    """Generate a proxy certificate.

     * new_pkey: EVP.PKey for the proxy certificate
     * cert: Issuer certificate
     * key: Issuer private key

    Optional arguments:

     * lifetime: proxy certificate lifetime, in seconds. Default: is 12 hours.
     * full: proxy type, full or limited. Default is False (limited proxy).
     * hash_algorithm: hash algorithm to use for certificate signing. Default: sha1.
     * globus_bug: do not use basicConstraints extension and do not allow Key Agreement. Default: true
    """
    args = kwargs.copy()
    if 'args' in args:
        args.update(args.pop('args'))

    legacy = args.get('legacy', is_legacy_proxy(cert))
    full = args.get('full', False)
    globus_bug = args.get('globus_bug', True)

    proxy = X509.X509()
    proxy.set_pubkey(new_pkey)
    proxy.set_version(2)

    now = int(time.time())
    not_before = ASN1.ASN1_UTCTIME()
    not_before.set_time(now  - CLOCK_SKEW)
    proxy.set_not_before(not_before)
    not_after = ASN1.ASN1_UTCTIME()
    not_after.set_time(now + args.get('lifetime', 12*60*60) + CLOCK_SKEW)
    proxy.set_not_after(not_after)

    proxy.set_issuer_name(cert.get_subject())
    digest = EVP.MessageDigest('sha1')
    digest.update(new_pkey.as_der())
    serial = struct.unpack("<L", digest.final()[:4])[0]
    proxy.set_serial_number(int(serial & 0x7fffffff))

    # It is not completely clear what happens with memory allocation
    # within the next calls, so after building the whole thing we are
    # going to reload it through der encoding/decoding.
    proxy_subject = X509.X509_Name()
    subject = cert.get_subject()
    for idx in xrange(subject.entry_count()):
        entry = subject[idx].x509_name_entry
        m2.x509_name_add_entry(proxy_subject._ptr(), entry, -1, 0)
    if legacy:
        if full:
            proxy_subject.add_entry_by_txt('CN',
                                           ASN1.MBSTRING_ASC,
                                           "proxy", -1, -1, 0)
        else:
            proxy_subject.add_entry_by_txt('CN',
                                           ASN1.MBSTRING_ASC,
                                           "limited proxy", -1, -1, 0)
    else:
        proxy_subject.add_entry_by_txt('CN',
                                       ASN1.MBSTRING_ASC,
                                       str(serial), -1, -1, 0)
    proxy.set_subject(proxy_subject)
    if legacy:
        if globus_bug:
            proxy.add_ext(X509.new_extension(
                "keyUsage",
                "Digital Signature, Key Encipherment, Data Encipherment", 1))
        else:
            proxy.add_ext(X509.new_extension(
                "keyUsage",
                "Digital Signature, Key Encipherment, Data Encipherment, Key Agreement", 1))
            proxy.add_ext(X509.new_extension("basicConstraints", "CA:FALSE", 1))

            # does not work (?) seems like need to add authorityCertIssuer
            # and authorityCertSerialNumber somehow, see rfc 3280 for more
            # details

            # try:
            #     subjkey = cert.get_ext('subjectKeyIdentifier')
            #     keyid = "keyid:%s" % subjkey.get_value()
            #     ext = X509.new_extension("authorityKeyIdentifier", keyid, 0)
            #     proxy.add_ext(ext)
            # except LookupError:
            #     pass
    else:
        if globus_bug:
            proxy.add_ext(X509.new_extension("keyUsage", "Digital Signature, Key Encipherment, Data Encipherment", 1))
        else:
            proxy.add_ext(X509.new_extension("basicConstraints", "CA:FALSE", 1))
            proxy.add_ext(X509.new_extension("keyUsage", "Digital Signature, Key Encipherment, Data Encipherment, Key Agreement", 1))
    if not legacy:
        if full:
            proxy.add_ext(X509.new_extension("proxyCertInfo",
                                             "critical, language:Inherit all",
                                             1))
        else:
            proxy.add_ext(X509.new_extension("proxyCertInfo",
                                             "critical, language:1.3.6.1.4.1.3536.1.1.1.9",
                                             1))

    sign_pkey = EVP.PKey()
    sign_pkey.assign_rsa(key, 0)
    proxy.sign(sign_pkey, args.get('hash_algorithm', 'sha1'))

    return X509.load_cert_string(proxy.as_pem())

def split_proxy(proxy):
    u"""
    Split the proxy string into two lists:
    * certs - certificates
    * keys - keys

    Returns (certs, keys)
    """
    lines = proxy.split("\n")
    result = ([], [])
    state = 3
    endtag = None
    buf = []
    while len(lines) > 0:
        line = lines[0]
        lines = lines[1:]

        if state != 2:
            buf.append(line)

        if line == endtag:
            if state < 2:
                result[state].append("\n".join(buf))
            state = 3
            endtag = None
            buf = []
            continue
            
        if state == 3:
            what = re.findall("^-----BEGIN (.*)-----$", line)
            if len(what) == 1:
                endtag = "-----END %s-----" % what[0]
                if what[0] == "CERTIFICATE":
                    state = 0
                elif what[0].endswith(" KEY"):
                    state = 1
                else:
                    state = 2
    return result
    
def load_proxy(proxy):
    """Load a proxy certificate from a string."""
    certs, keys = split_proxy(proxy)
    if len(keys) != 0:
        key = RSA.load_key_string(keys[0])
    else:
        key = None
    chain = X509.X509_Stack()
    for pem in certs:
        chain.push(X509.load_cert_string(pem))

    return key, chain

def is_legacy_proxy(cert):
    """Check if certificate is a legacy proxy certificate"""
    for i in xrange(cert.get_ext_count()):
        ext = cert.get_ext_at(i)
        if ext.get_name().lower() == "proxycertinfo":
            return False
    for entry in cert.get_subject():
        # M2Crypto 0.16 does not implement the corresponding python api :(
        obj = m2.x509_name_entry_get_object(entry._ptr())
        objname = m2.obj_nid2sn(m2.obj_obj2nid(obj))
        val = entry.get_data().as_text()
        if objname == 'CN' and val in ('proxy', 'limited proxy'):
            return True
    return False
