# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the author be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.

"""Tests for the strict display-layer verification (verify_for_display).

All keys are generated locally and all public key lookups go through an
in-memory DNS callback; nothing here touches the network.  Every test
checks three things together: the cryptographic signature result, the
exact original-header indices that participated in the digest, and the
display policy conclusion.
"""

import base64
import unittest

import dkim
from dkim.canonicalization import CanonicalizationPolicy

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


CRLF = b"\r\n"


def make_key():
    """Generate a fresh RSA key pair, returning (PEM private key, DKIM p= value)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    pub_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, base64.b64encode(pub_der).decode("ascii")


def build_message(headers, body, linesep=CRLF):
    """Build an RFC822 message from (name, value) header pairs and a body."""
    text = b""
    for name, value in headers:
        text += name + b": " + value + linesep
    text += linesep + body
    return text


def expected_indices(message, include_headers):
    """Independently compute which original header indices h= selects."""
    d = dkim.DKIM(message)
    _, indices = dkim.select_headers_with_indices(d.headers, include_headers)
    return indices, d


class TestVerifyForDisplay(unittest.TestCase):

    def setUp(self):
        self.privkey, self.pub_p = make_key()
        self.domain = b"example.com"
        self.selector = b"test"
        # In-memory DNS: any lookup outside this table is a test failure,
        # guaranteeing no real DNS traffic.
        self.dns_lookups = []

        def dnsfunc(name, timeout=5):
            if isinstance(name, bytes):
                name = name.decode("ascii")
            self.dns_lookups.append(name)
            table = {
                "test._domainkey.example.com.":
                    "v=DKIM1; k=rsa; p=%s" % self.pub_p,
                "weak._domainkey.example.com.":
                    "v=DKIM1; k=rsa; p=%s" % self.pub_p,
                "strong._domainkey.example.com.":
                    "v=DKIM1; k=rsa; p=%s" % self.pub_p,
            }
            self.assertIn(name, table, "unexpected (real?) DNS lookup: %s" % name)
            return table[name]

        self.dnsfunc = dnsfunc

        self.headers = [
            (b"From", b"alice@example.com"),
            (b"To", b"bob@example.org"),
            (b"Subject", b"display policy test"),
            (b"Date", b"Mon, 01 Jan 2024 00:00:00 +0000"),
        ]
        self.body = b"hello body\r\nsecond line\r\n"
        self.message = build_message(self.headers, self.body)
        self.full_include = [b"from", b"to", b"subject", b"date"]

    def sign(self, message, include_headers, selector=None, length=False,
             canonicalize=(b"relaxed", b"simple")):
        selector = selector or self.selector
        return dkim.sign(
            message, selector, self.domain, self.privkey,
            include_headers=include_headers, length=length,
            canonicalize=canonicalize)

    def display(self, signed, required=(b"from", b"subject", b"to")):
        return dkim.verify_for_display(
            signed, required_headers=required, dnsfunc=self.dnsfunc)

    def test_basic_pass_every_canonicalization(self):
        # All four simple/relaxed combinations must pass, with the exact
        # original header indices reported.
        for hc in (b"simple", b"relaxed"):
            for bc in (b"simple", b"relaxed"):
                sig = self.sign(
                    self.message, self.full_include,
                    canonicalize=(hc, bc))
                signed = sig + self.message
                self.assertTrue(dkim.verify(signed, dnsfunc=self.dnsfunc))
                results = self.display(signed)
                self.assertEqual(len(results), 1)
                r = results[0]
                self.assertTrue(r["result"], r["reason"])
                self.assertTrue(r["cryptographic_result"])
                self.assertTrue(r["body_fully_covered"])
                self.assertEqual(r["domain"], self.domain)
                self.assertEqual(r["selector"], self.selector)
                # DKIM-Signature is index 0 in the signed message.
                exp, _ = expected_indices(signed, self.full_include)
                self.assertEqual(r["signed_header_indices"], exp)
                self.assertEqual(
                    sorted(r["signed_header_indices"]),
                    sorted(exp))

    def test_indices_are_original_positions_top_to_bottom(self):
        # Two To fields; digest order must pick the bottom instance first.
        headers = self.headers + [(b"To", b"carol@example.net")]
        message = build_message(headers, self.body)
        include = [b"from", b"to", b"subject", b"to"]
        sig = self.sign(message, include)
        signed = sig + message
        r = self.display(signed)[0]
        self.assertTrue(r["result"], r["reason"])
        d = dkim.DKIM(signed)
        to_positions = [i for i, (n, v) in enumerate(d.headers)
                        if n.lower() == b"to"]
        self.assertEqual(len(to_positions), 2)
        # Both existing instances selected, bottom one first in digest.
        self.assertEqual(
            [i for i in r["signed_header_indices"]
             if d.headers[i][0].lower() == b"to"],
            list(reversed(to_positions)))

    def test_repeated_header_not_fully_covered_is_rejected(self):
        # Two To fields but h= only signs one: crypto still valid, the
        # boolean interface says True, yet the display policy refuses.
        headers = self.headers + [(b"To", b"carol@example.net")]
        message = build_message(headers, self.body)
        include = [b"from", b"to", b"subject"]
        sig = self.sign(message, include)
        signed = sig + message
        self.assertTrue(dkim.verify(signed, dnsfunc=self.dnsfunc))
        r = self.display(signed)[0]
        self.assertFalse(r["result"])
        self.assertTrue(r["cryptographic_result"])
        self.assertIn("to", r["reason"].lower())
        d = dkim.DKIM(signed)
        signed_to = [i for i in r["signed_header_indices"]
                     if d.headers[i][0].lower() == b"to"]
        all_to = [i for i, (n, v) in enumerate(d.headers)
                  if n.lower() == b"to"]
        self.assertEqual(len(signed_to), 1)
        self.assertNotEqual(sorted(signed_to), sorted(all_to))

    def test_duplicate_h_selection_and_oversigning(self):
        # subject repeated in h= while only one instance exists, plus a
        # wholly absent header over-signed twice: no phantom indices may
        # appear, and the policy still passes.
        include = [b"from", b"to", b"subject", b"subject",
                   b"x-does-not-exist", b"x-does-not-exist"]
        sig = self.sign(self.message, include)
        signed = sig + self.message
        r = self.display(signed)[0]
        self.assertTrue(r["result"], r["reason"])
        exp, _ = expected_indices(signed, include)
        self.assertEqual(r["signed_header_indices"], exp)
        d = dkim.DKIM(signed)
        # Every reported index must be a real header, none invented.
        self.assertTrue(
            all(0 <= i < len(d.headers)
                for i in r["signed_header_indices"]))
        self.assertNotIn(
            b"x-does-not-exist",
            [d.headers[i][0].lower()
             for i in r["signed_header_indices"]])

    def test_legitimate_from_oversigning_passes(self):
        # from listed twice with a single From instance is the standard
        # anti-addition oversign and must pass.
        include = [b"from", b"from", b"to", b"subject"]
        sig = self.sign(self.message, include)
        signed = sig + self.message
        r = self.display(signed)[0]
        self.assertTrue(r["result"], r["reason"])
        d = dkim.DKIM(signed)
        from_positions = [i for i, (n, v) in enumerate(d.headers)
                          if n.lower() == b"from"]
        self.assertEqual(
            [i for i in r["signed_header_indices"]
             if d.headers[i][0].lower() == b"from"],
            from_positions)

    def test_two_from_fields_always_rejected(self):
        # Even if both From instances are cryptographically signed, the
        # display policy demands exactly one From.
        headers = [(b"From", b"alice@example.com"),
                   (b"From", b"mallory@example.com")] + self.headers[1:]
        message = build_message(headers, self.body)
        include = [b"from", b"from", b"to", b"subject"]
        sig = self.sign(message, include)
        signed = sig + message
        self.assertTrue(dkim.verify(signed, dnsfunc=self.dnsfunc))
        r = self.display(signed)[0]
        self.assertFalse(r["result"])
        self.assertTrue(r["cryptographic_result"])
        self.assertIn("from", r["reason"].lower())

    def test_required_header_missing_rejected(self):
        headers = [(b"From", b"alice@example.com"),
                   (b"Subject", b"no to here")]
        message = build_message(headers, self.body)
        # Oversign the absent To; the signature itself is perfectly valid.
        include = [b"from", b"subject", b"to"]
        sig = self.sign(message, include)
        signed = sig + message
        self.assertTrue(dkim.verify(signed, dnsfunc=self.dnsfunc))
        r = self.display(signed)[0]
        self.assertFalse(r["result"])
        self.assertIn(b"to", r["reason"].encode())

    def test_case_insensitive_required_names(self):
        sig = self.sign(self.message, self.full_include)
        signed = sig + self.message
        for required in ((b"FROM", b"Subject", b"to"),
                         ("from", "subject", "to"),
                         (b"FrOm", b"SuBjEcT", b"To")):
            r = self.display(signed, required=required)[0]
            self.assertTrue(r["result"], (required, r["reason"]))

    def test_custom_required_header(self):
        headers = self.headers + [(b"X-Confidential", b"yes")]
        message = build_message(headers, self.body)
        sig_covered = self.sign(
            message, self.full_include + [b"x-confidential"])
        r = self.display(sig_covered + message,
                         required=(b"from", b"x-confidential"))[0]
        self.assertTrue(r["result"], r["reason"])

        sig_plain = self.sign(message, self.full_include)
        r = self.display(sig_plain + message,
                         required=(b"from", b"x-confidential"))[0]
        self.assertFalse(r["result"])
        self.assertIn("x-confidential", r["reason"].lower())

    def test_l_tag_covering_full_body_passes(self):
        for bc in (b"simple", b"relaxed"):
            sig = self.sign(
                self.message, self.full_include, length=True,
                canonicalize=(b"relaxed", bc))
            signed = sig + self.message
            # l= must equal the length of the fully canonicalized body.
            policy = CanonicalizationPolicy.from_c_value(
                b"relaxed/" + bc)
            self.assertIn(
                b"l=%d" % len(policy.canonicalize_body(
                    dkim.DKIM(self.message).body)),
                sig)
            r = self.display(signed)[0]
            self.assertTrue(r["result"], r["reason"])
            self.assertTrue(r["body_fully_covered"])

    def test_l_tag_prefix_with_appended_body_rejected(self):
        # Sign with l= over the original body, then append an unsigned
        # tail (e.g. a mailing list footer).  RFC 6376 verification and
        # the boolean interface still pass; the display policy must not.
        sig = self.sign(self.message, self.full_include, length=True)
        tampered = sig + self.message + b"unsigned mailing list footer\r\n"
        self.assertTrue(dkim.verify(tampered, dnsfunc=self.dnsfunc))
        r = self.display(tampered)[0]
        self.assertFalse(r["result"])
        self.assertTrue(r["cryptographic_result"])
        self.assertFalse(r["body_fully_covered"])
        self.assertIn("body", r["reason"].lower())

    def test_relaxed_body_whitespace_and_l_tag(self):
        # Relaxed canonicalization strips trailing WSP and blank tail
        # lines; l= computed on that canonical body still covers all of
        # it, so the display policy passes.
        body = b"line one   \r\n\r\n\r\n"
        message = build_message(self.headers, body)
        sig = self.sign(
            message, self.full_include, length=True,
            canonicalize=(b"relaxed", b"relaxed"))
        r = self.display(sig + message)[0]
        self.assertTrue(r["result"], r["reason"])
        self.assertTrue(r["body_fully_covered"])
        # Appending after signing changes the canonicalized body length.
        r2 = self.display(
            sig + message + b"extra\r\n")[0]
        self.assertFalse(r2["result"])
        self.assertFalse(r2["body_fully_covered"])

    def test_tampered_signed_header_fails_crypto(self):
        sig = self.sign(self.message, self.full_include)
        signed = sig + self.message
        tampered = signed.replace(b"display policy test",
                                  b"changed subject")
        r = self.display(tampered)[0]
        self.assertFalse(r["result"])
        self.assertFalse(r["cryptographic_result"])
        self.assertIn("cryptographic", r["reason"])

    def test_tampered_unsigned_header_still_passes(self):
        # A header outside the required set that was not signed may
        # change without affecting display protection of what matters.
        headers = self.headers + [(b"X-Transit", b"one")]
        message = build_message(headers, self.body)
        sig = self.sign(message, self.full_include)
        tampered = (sig + message).replace(b"X-Transit: one",
                                           b"X-Transit: two")
        self.assertTrue(dkim.verify(tampered, dnsfunc=self.dnsfunc))
        r = self.display(tampered)[0]
        self.assertTrue(r["result"], r["reason"])

    def test_two_signatures_weak_then_strong(self):
        # Signature 0 only protects From (valid but weak); signature 1
        # protects everything.  Only signature 1 may pass, and state
        # from signature 0 must not leak into signature 1's result.
        weak_sig = self.sign(
            self.message, [b"from", b"from"], selector=b"weak")
        strong_sig = self.sign(
            self.message,
            [b"from", b"to", b"subject", b"from"], selector=b"strong")
        # weak_sig is prepended last, so it is the topmost (index 0).
        signed = weak_sig + strong_sig + self.message
        results = self.display(signed)
        self.assertEqual(len(results), 2)
        weak, strong = results
        self.assertEqual(weak["signature_index"], 0)
        self.assertEqual(strong["signature_index"], 1)
        self.assertFalse(weak["result"])
        self.assertTrue(weak["cryptographic_result"])
        self.assertTrue(strong["result"], strong["reason"])
        # The weak signature's From-only indices cannot endorse the
        # strong signature's result.
        d = dkim.DKIM(signed)
        weak_names = [d.headers[i][0].lower()
                      for i in weak["signed_header_indices"]]
        self.assertEqual(set(weak_names), {b"from"})
        # The second from in h= over-signs an absent instance and so
        # selects nothing: exactly three real instances are reported.
        strong_names = sorted(d.headers[i][0].lower()
                              for i in strong["signed_header_indices"])
        self.assertEqual(
            strong_names, [b"from", b"subject", b"to"])
        exp, _ = expected_indices(
            signed, [b"from", b"to", b"subject", b"from"])
        self.assertEqual(strong["signed_header_indices"], exp)

    def test_failed_signature_then_valid_signature(self):
        # A broken first signature must not prevent a sound second one
        # from passing on its own merits.
        good_sig = self.sign(
            self.message, self.full_include, selector=b"strong")
        weak_sig = self.sign(
            self.message, [b"from"], selector=b"weak")
        # Corrupt the base64 b= value of the weak (topmost) signature.
        pos = weak_sig.rindex(b"b=") + 2
        broken = weak_sig[:pos] + b"AA" + weak_sig[pos + 2:]
        signed = broken + good_sig + self.message
        results = self.display(signed)
        self.assertEqual(len(results), 2)
        self.assertFalse(results[0]["result"])
        self.assertFalse(results[0]["cryptographic_result"])
        self.assertTrue(results[1]["result"], results[1]["reason"])
        self.assertTrue(results[1]["cryptographic_result"])

    def test_malformed_signature_is_isolated(self):
        good_sig = self.sign(self.message, self.full_include)
        garbage = b"DKIM-Signature: v=1; this is not tag value data\r\n"
        # garbage is prepended last, so it is the topmost (index 0).
        signed = garbage + good_sig + self.message
        results = self.display(signed)
        self.assertEqual(len(results), 2)
        self.assertFalse(results[0]["result"])
        self.assertIn("rejected", results[0]["reason"])
        self.assertTrue(results[1]["result"], results[1]["reason"])

    def test_no_signatures_returns_empty_list(self):
        self.assertEqual(self.display(self.message), [])

    def test_original_message_bytes_unchanged(self):
        sig = self.sign(self.message, self.full_include)
        signed = sig + self.message
        snapshot = bytes(signed)
        self.display(signed)
        self.assertEqual(signed, snapshot)
        self.assertEqual(self.message, build_message(self.headers, self.body))

    def test_result_dict_shape(self):
        sig = self.sign(self.message, self.full_include)
        r = self.display(sig + self.message)[0]
        self.assertEqual(
            set(r),
            {"result", "signature_index", "domain", "selector",
             "signed_header_indices", "reason",
             "cryptographic_result", "body_fully_covered"})
        self.assertIsInstance(r["signed_header_indices"], list)
        self.assertTrue(all(isinstance(i, int)
                            for i in r["signed_header_indices"]))

    def test_only_in_memory_dns_used(self):
        sig = self.sign(self.message, self.full_include)
        self.display(sig + self.message)
        self.assertTrue(self.dns_lookups)
        self.assertTrue(
            all(name.endswith("example.com.") for name in self.dns_lookups))


def test_suite():
    from unittest import TestLoader
    return TestLoader().loadTestsFromName(__name__)
