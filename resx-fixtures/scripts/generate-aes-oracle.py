import gzip
import json
import random
import sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography import __version__

root=Path(sys.argv[1]).resolve()
root.mkdir(exist_ok=False)
rng=random.Random(20260910)
cases=[]
for index in range(48):
    key=rng.randbytes([16,24,32][index%3]);iv=rng.randbytes(16)
    padding=index%2==0
    raw=rng.randbytes(index*29 if padding else index*16)
    input_bytes=raw
    if padding:
        padder=PKCS7(128).padder();input_bytes=padder.update(raw)+padder.finalize()
    encryptor=Cipher(algorithms.AES(key),modes.CBC(iv)).encryptor()
    encrypted=encryptor.update(input_bytes)+encryptor.finalize()
    name=f'{index:02d}'
    (root/(name+'.key')).write_bytes(key)
    (root/(name+'.ciphertext')).write_bytes(encrypted)
    (root/(name+'.expected')).write_bytes(raw)
    cases.append({'name':name,'iv':iv.hex(),'padding':padding})
raw=json.dumps({'endpoint':'https://fixture.invalid/encrypted-config','fixture':True}).encode()
compressed=gzip.compress(raw,mtime=0)
key=bytes(range(32));iv=bytes(range(16))
padder=PKCS7(128).padder();padded=padder.update(compressed)+padder.finalize()
encryptor=Cipher(algorithms.AES(key),modes.CBC(iv)).encryptor()
(root/'config.key').write_bytes(key)
(root/'config.encrypted').write_bytes(encryptor.update(padded)+encryptor.finalize())
(root/'config.expected').write_bytes(raw)
(root/'manifest.json').write_text(json.dumps({'oracle':'Installed Python cryptography package','version':__version__,'seed':20260910,'cases':cases},indent=2))
print(json.dumps({'cases':len(cases),'root':str(root),'keys':'Task-generated test keys only'}))
