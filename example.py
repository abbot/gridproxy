#!/usr/bin/env python

import gridproxy
import gridproxy.voms

v = gridproxy.voms.VOMS()
k, p = gridproxy.load_proxy(open(gridproxy.get_proxy_filename(), "r").read())
v.from_x509_stack(p)
if gridproxy.is_legacy_proxy(p[0]):
    t = "globus legacy proxy"
else:
    t = "RFC compliant proxy"

print "subject   :", p[0].get_subject()
print "identity  :", v.user
print "CA        :", v.userca
print "type      :", t
print "FQANs     :", ", ".join(v.fqans)
print "VOMS URI  :", v.uri
print "VOMS Srv  :", v.server
print "VOMS CA   :", v.serverca
print "Validity  :", v.not_before.strftime("%c %Z"), "-", v.not_after.strftime("%c %Z")
