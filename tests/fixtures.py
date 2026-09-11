"""Structured test records; DNS data is persisted only in LMDB."""
import base64
import json
import subprocess
import dns.rdata
import dns.rdatatype
import dns.rrset

ROWS = [('example.test.', 'A', 60, '192.0.2.10'), ('example.test.', 'AAAA', 120, '2001:db8::10'), ('text.test.', 'TXT', 300, '"hello world" "second string"'), ('spf.test.', 'TXT', 300, '"v=spf1 ip4:192.0.2.0/24 -all"'), ('legacy.test.', 'SPF', 300, '"v=spf1 -all"'), ('mail.test.', 'MX', 300, '10 mail1.test.'), ('mail.test.', 'MX', 300, '20 mail2.test.'), ('ns.test.', 'NS', 300, 'ns1.test.'), ('alias.test.', 'CNAME', 300, 'example.test.'), ('ptr.test.', 'PTR', 300, 'example.test.'), ('_service._tcp.test.', 'SRV', 300, '10 20 443 example.test.'), ('test.', 'SOA', 300, 'ns1.test. hostmaster.test. 2026091101 3600 600 86400 300'), ('caa.test.', 'CAA', 300, '0 issue "letsencrypt.org"'), ('hinfo.test.', 'HINFO', 300, '"ARM64" "Linux"'), ('naptr.test.', 'NAPTR', 300, '10 20 "s" "SIP+D2U" "" _sip._udp.test.'), ('sshfp.test.', 'SSHFP', 300, '1 1 0123456789abcdef0123456789abcdef01234567'), ('tlsa.test.', 'TLSA', 300, '3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'), ('https.test.', 'HTTPS', 300, '1 . alpn="h2,h3" port="443"'), ('svcb.test.', 'SVCB', 300, '1 example.test. port="8443"'), ('rp.test.', 'RP', 300, 'hostmaster.test. text.test.'), ('dname.test.', 'DNAME', 300, 'example.test.'), ('ds.test.', 'DS', 300, '12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'), ('dnskey.test.', 'DNSKEY', 300, '257 3 13 AQIDBA=='), ('cdnskey.test.', 'CDNSKEY', 300, '257 3 13 AQIDBA=='), ('cds.test.', 'CDS', 300, '12345 13 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'), ('nsec.test.', 'NSEC', 300, 'next.test. A TXT AAAA RRSIG NSEC'), ('nsec3param.test.', 'NSEC3PARAM', 300, '1 0 10 aabb'), ('rrsig.test.', 'RRSIG', 300, 'A 13 2 300 20300101000000 20260101000000 12345 test. AQIDBA=='), ('unknown.test.', 'TYPE65280', 300, '\\# 4 deadbeef')]

def record(name, kind, data, ttl=300):
    return {"name":name, "recordType":kind, "ttl":ttl, "data":data}

def inputs():
    return [{"name":name, "recordType":kind, "ttl":ttl,
             "rdataBase64":base64.b64encode(dns.rdata.from_text(1,kind,text).to_wire()).decode()}
            for name,kind,ttl,text in ROWS]

def expected_rrsets():
    groups = {}
    for name,kind,ttl,text in ROWS:
        key = (name,kind,ttl)
        groups.setdefault(key, []).append(text)
    return [dns.rrset.from_text(name,ttl,"IN",kind,*texts)
            for (name,kind,ttl),texts in groups.items()]

def write(binary, args, records):
    result = subprocess.run([str(binary), *args, "write"], input=json.dumps(records),
                            capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise AssertionError(result.stderr)
    return result
