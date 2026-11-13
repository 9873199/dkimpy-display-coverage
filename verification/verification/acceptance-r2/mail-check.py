import importlib.util,sys
from pathlib import Path
import dkim
from dkim_api import review
def load(name,file):
 spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
fixtures=load('mail_fixtures','dkim-display-fixtures.py');extra=load('mail_exact_cases','test_dkim_exact_contract.py')
cases,dnsfunc=fixtures.cases()
for name in ('simple-whole-body','simple-unsigned-body-tail','weak-before-strong'):
 case=next(x for x in cases if x.name==name);values=review(case.message,dnsfunc=dnsfunc)
 print(name+':',[(v['index'],v['passed'],v['covered']) for v in values])
normal=next(x for x in cases if x.name=='simple-whole-body');print('Custom required header Subject:',review(normal.message,dnsfunc=dnsfunc,required_headers=['Subject']))
message,callback=extra.oversize_length_fixture();print('Declared l=999, cryptographic check:',dkim.verify(message,dnsfunc=callback));print('Display decision:',review(message,dnsfunc=callback))
