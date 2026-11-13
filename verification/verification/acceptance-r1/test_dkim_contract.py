"""Check display coverage against raw header instances and real signatures.

dkim_api.review maps only the final public entry point and result shape. It
cannot add missing signature selection or coverage policy.
"""
import importlib.util
from pathlib import Path
import re
import sys

import dkim
import pytest
from dkim_api import review

spec = importlib.util.spec_from_file_location(
    'display_signed_fixtures', Path(__file__).with_name('dkim-display-fixtures.py'))
fixtures = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = fixtures
spec.loader.exec_module(fixtures)


def raw_headers(message):
    result = []
    for line in message.split(b'\r\n\r\n', 1)[0].split(b'\r\n'):
        if line.startswith((b' ', b'\t')):
            name, value = result[-1]
            result[-1] = (name, value + b'\r\n' + line)
        else:
            name, value = line.split(b':', 1)
            result.append((name.lower(), value))
    return result


def selected_indices(message, signature_index):
    headers = raw_headers(message)
    signatures = [value for name, value in headers if name == b'dkim-signature']
    unfolded = re.sub(br'\r\n[ \t]+', b' ', signatures[signature_index])
    tags = dict(part.strip().split(b'=', 1) for part in unfolded.split(b';')
                if b'=' in part)
    names = [name.strip().lower() for name in tags[b'h'].split(b':')]
    used = set()
    selected = []
    for name in names:
        for index in range(len(headers) - 1, -1, -1):
            if index not in used and headers[index][0] == name:
                used.add(index)
                selected.append(index)
                break
    return selected


@pytest.fixture(scope='module')
def generated():
    return fixtures.cases()


@pytest.mark.parametrize('case_index', range(14))
def test_coverage_follows_the_actual_signature_and_header_instances(generated, case_index):
    cases, dnsfunc = generated
    case = cases[case_index]
    original = bytes(case.message)
    actual_crypto = tuple(bool(dkim.DKIM(original).verify(idx=i, dnsfunc=dnsfunc))
                          for i in range(len(case.cryptographic)))
    assert actual_crypto == case.cryptographic, 'Cryptographic fixture control failed'
    results = review(original, dnsfunc=dnsfunc)
    assert len(results) == len(case.display)
    assert [item['index'] for item in results] == list(range(len(case.display)))
    assert tuple(item['passed'] for item in results) == case.display, case.name
    for index, item in enumerate(results):
        assert item['domain'] == 'example.invalid'
        assert item['selector'] == 'local'
        if case.cryptographic[index]:
            assert sorted(item['covered']) == sorted(selected_indices(original, index)), case.name
            assert len(item['covered']) == len(set(item['covered']))
        if not case.display[index]:
            assert item['reasons'], 'A rejected signature needs an observable reason'
    assert case.message == original


def test_requested_header_names_are_case_insensitive(generated):
    cases, dnsfunc = generated
    case = next(case for case in cases if case.name == 'simple-whole-body')
    results = review(case.message, dnsfunc=dnsfunc,
                     required_headers=['fRoM', 'sUBJECT', 'TO'])
    assert len(results) == 1 and results[0]['passed']


def test_missing_requested_header_is_rejected_even_with_valid_signature(generated):
    cases, dnsfunc = generated
    case = next(case for case in cases if case.name == 'relaxed-whole-body')
    assert dkim.verify(case.message, dnsfunc=dnsfunc)
    results = review(case.message, dnsfunc=dnsfunc,
                     required_headers=['From', 'Subject', 'To', 'X-Display-Identity'])
    assert len(results) == 1 and not results[0]['passed']
    assert results[0]['reasons']
