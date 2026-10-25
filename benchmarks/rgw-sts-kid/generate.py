import base64, datetime, json, sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

def b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip('=')
def uint(i):
    return b64(i.to_bytes((i.bit_length()+7)//8, 'big'))
root=Path(sys.argv[1] if len(sys.argv)>1 else 'fixtures');root.mkdir(parents=True,exist_ok=True)
keys=[];private=[]
for i in range(32):
    k=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    private.append(k)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f'local-bench-{i}')])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name)
          .public_key(k.public_key()).serial_number(i+1)
          .not_valid_before(now-datetime.timedelta(days=1))
          .not_valid_after(now+datetime.timedelta(days=30)).sign(k,hashes.SHA256()))
    nums=k.public_key().public_numbers()
    keys.append({'kid':f'key-{i}','kty':'RSA','use':'sig','alg':'RS256',
                 'n':uint(nums.n),'e':uint(nums.e),
                 'x5c':[base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()]})
for n in [1,4,8,16,32]:
    for path in ['ne','x5c']:
        fixture=[{field:v for field,v in key.items() if field not in (['x5c'] if path=='ne' else ['n','e'])} for key in keys[:n]]
        (root/f'{path}-{n}.json').write_text(json.dumps({'keys':fixture},separators=(',',':')))

def token(index, kid):
    header={'alg':'RS256','typ':'JWT'}
    if kid is not None: header['kid']=kid
    payload={'iss':'https://local-benchmark.invalid','sub':'test-service-account','aud':'rgw-benchmark'}
    message=b64(json.dumps(header,separators=(',',':')).encode())+'.'+b64(json.dumps(payload,separators=(',',':')).encode())
    return message+'.'+b64(private[index].sign(message.encode(),padding.PKCS1v15(),hashes.SHA256()))
for i in range(32):
    (root/f'token-{i}.jwt').write_text(token(i,f'key-{i}'))
(root/'missing.jwt').write_text(token(0,None))
(root/'unknown.jwt').write_text(token(0,'unknown'))
(root/'wrong-known.jwt').write_text(token(0,'key-1'))
(root/'empty.jwt').write_text(token(0,''))
print('Generated synthetic RSA-2048 keys, certificates and signed JWTs. No cluster credentials used.')

single=json.loads((root/'ne-1.json').read_text())
del single['keys'][0]['kid']
(root/'ne-1-no-jwk-kid.json').write_text(json.dumps(single))
