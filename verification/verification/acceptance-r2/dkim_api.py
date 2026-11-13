"""Map final public result shape only; no coverage policy is implemented here."""
import dkim
def review(message,**kwargs):
    values=dkim.verify_for_display(message,**kwargs)
    assert isinstance(values,list)
    def text(v):return v.decode('ascii') if isinstance(v,bytes) else v
    return [{'index':v['signature_index'],'passed':v['result'],'domain':text(v['domain']),'selector':text(v['selector']),'covered':v['signed_header_indices'],'reasons':[v['reason']] if v['reason'] else []} for v in values]
