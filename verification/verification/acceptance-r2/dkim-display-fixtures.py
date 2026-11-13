"""In-memory signatures with independent expected display-coverage cases."""
import base64
from dataclasses import dataclass

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class Case:
    name: str
    message: bytes
    cryptographic: tuple
    display: tuple


def cases():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    record = b'v=DKIM1; k=rsa; p=' + base64.b64encode(public)
    def dnsfunc(name, timeout=5):
        assert name == b'local._domainkey.example.invalid.'
        return record
    head = b'From: Sender <sender@example.invalid>\r\nTo: Reader <reader@example.invalid>\r\nSubject: expected title\r\n'
    body = b'Protected body.\r\n'
    message = head + b'\r\n' + body
    def signature(msg, include=(b'from', b'subject', b'to'), canon=(b'relaxed', b'relaxed'), length=False):
        return dkim.sign(msg, b'local', b'example.invalid', private,
            canonicalize=canon, include_headers=include, length=length)
    results = []
    for canon in ((b'simple', b'simple'), (b'relaxed', b'relaxed')):
        label = canon[1].decode()
        sig = signature(message, canon=canon)
        results.append(Case(label + '-whole-body', sig + message, (True,), (True,)))
        sig_l = signature(message, canon=canon, length=True)
        results.append(Case(label + '-exact-l', sig_l + message, (True,), (True,)))
        results.append(Case(label + '-unsigned-body-tail', sig_l + message + b'Unsigned addition.\r\n', (True,), (False,)))
        results.append(Case(label + '-trailing-empty-lines', sig_l + message + b'\r\n\r\n', (True,), (True,)))
    unsigned = b'Subject: unsigned title\r\n' + message
    results.append(Case('duplicate-subject-one-selected', signature(unsigned) + unsigned, (True,), (False,)))
    results.append(Case('duplicate-subject-both-selected', signature(unsigned, include=(b'from', b'subject', b'subject', b'to')) + unsigned, (True,), (True,)))
    results.append(Case('oversigning-no-phantom-instance', signature(message, include=(b'from', b'subject', b'subject', b'to', b'to')) + message, (True,), (True,)))
    duplicate_from = b'From: Other <other@example.invalid>\r\n' + message
    results.append(Case('duplicate-from-both-signed', signature(duplicate_from, include=(b'from', b'from', b'subject', b'to')) + duplicate_from, (True,), (False,)))
    strong = signature(message)
    weak = signature(message, include=(b'from',))
    results.append(Case('weak-before-strong', weak + strong + message, (True, True), (False, True)))
    damaged = bytearray(strong)
    index = damaged.index(b'b=') + 2
    damaged[index] = ord('B') if damaged[index] == ord('A') else ord('A')
    results.append(Case('bad-before-strong', bytes(damaged) + strong + message, (False, True), (False, True)))
    return results, dnsfunc


def header_instances(message):
    """Raw top-to-bottom instances, including each folded signature as one field."""
    result = []
    for line in message.split(b'\r\n\r\n', 1)[0].split(b'\r\n'):
        if line.startswith((b' ', b'\t')):
            continue
        name = line.split(b':', 1)[0].lower()
        result.append(name)
    return result


if __name__ == '__main__':
    import json
    generated, dnsfunc = cases()
    observations = []
    for case in generated:
        actual = tuple(bool(dkim.DKIM(case.message).verify(idx=i, dnsfunc=dnsfunc)) for i in range(len(case.cryptographic)))
        assert actual == case.cryptographic, (case.name, actual, case.cryptographic)
        observations.append({'case': case.name, 'actual_signature_validity': actual,
            'expected_display_policy': case.display, 'original_header_names': [x.decode() for x in header_instances(case.message)]})
    print(json.dumps({'signature_positive_and_negative_controls': observations, 'dns_network_used': False, 'private_key_logged': False}))
