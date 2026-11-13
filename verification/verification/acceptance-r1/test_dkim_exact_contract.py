"""Exact l= and independent From constraint with genuine RSA signatures."""
import base64,hashlib,importlib.util,re,sys
from pathlib import Path
import dkim,pytest
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding,utils
from dkim_api import review

def oversize_length_fixture():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    pem=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption())
    public=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    def dnsfunc(name,timeout=5):
        assert name==b'local._domainkey.example.invalid.'
        return b'v=DKIM1; k=rsa; p='+base64.b64encode(public)
    message=b'From: sender@example.invalid\r\nTo: reader@example.invalid\r\nSubject: title\r\n\r\nProtected body.\r\n'
    sig=dkim.sign(message,b'local',b'example.invalid',pem,include_headers=[b'from',b'subject',b'to'],length=True)
    sig=re.sub(br'(?<=l=)\d+',b'999',sig)
    obj=dkim.DKIM(sig+message);pair=obj.headers[0];tags=dkim.parse_tag_value(pair[1]);policy=dkim.CanonicalizationPolicy.from_c_value(tags.get(b'c'))
    digest=hashlib.sha256();dkim.hash_headers(digest,policy,policy.canonicalize_headers(obj.headers),[b'from',b'subject',b'to'],pair,tags)
    signature=key.sign(digest.digest(),padding.PKCS1v15(),utils.Prehashed(hashes.SHA256()))
    value=dkim.RE_BTAG.sub(lambda m:m.group(1)+base64.b64encode(signature),pair[1])
    signed=pair[0]+b':'+value+message
    assert dkim.verify(signed,dnsfunc=dnsfunc),'Cryptographic control must pass before testing display policy'
    return signed,dnsfunc

def test_declared_larger_l_is_not_exact_coverage():
    message,dnsfunc=oversize_length_fixture()
    result=review(message,dnsfunc=dnsfunc)
    assert len(result)==1 and not result[0]['passed'],'l=999 exceeds full canonical body and must fail exact-l display policy'

@pytest.mark.parametrize('required',[[b'subject',b'to'],['Subject']])
def test_from_exactly_once_is_independent_of_custom_required_names(required):
    path=Path(__file__).with_name('dkim-display-fixtures.py');spec=importlib.util.spec_from_file_location('subset_fixture',path);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    cases,dnsfunc=module.cases();case=next(x for x in cases if x.name=='simple-whole-body');assert dkim.verify(case.message,dnsfunc=dnsfunc)
    result=review(case.message,dnsfunc=dnsfunc,required_headers=required)
    assert len(result)==1 and result[0]['passed'],'Actual From exists exactly once even when required list names only display-specific fields'

if __name__=='__main__':
    message,dnsfunc=oversize_length_fixture();print({'ordinary_signature_valid':dkim.verify(message,dnsfunc=dnsfunc),'declared_l':999,'strict_result':review(message,dnsfunc=dnsfunc)})
