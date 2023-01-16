# General knowledge

## Converting data

### Binary to hexadecimal
Use python built-in functions.
```python
bin_data = b"data"
hex_data = bin_data.hex()
bin_data = bytes.fromhex(hex_data)
```

### Binary to base 64
Use python module \textbf{base64}.
```python
import base64

bin_data = b"data"
b64_data = base64.b64encode(bin_data)
bin_data = base64.b64decode(b64_data)
```

## PKCS7 Padding
Some block cyphers might require padding. The order of operation must always be:
1. Pad data
2. Encrypt padded data
3. Exchange data
4. Decrypt encrypted data
5. Unpad plaintext

```python
from cryptography.hazmat.primitives import padding

padder = padding.PKCS7(block_size).padder()
padded_data = padder.update(data) + padder.finalize()

unpadder = padding.PKCS7(block_size).unpadder()
data = unpadder.update(padded_data) + unpadder.finalize()

```


## Randomization
### Random keystream
You can generate a random string of bytes by using an OS function.

```python
import os

rand = os.urandom(num_bytes)
```

### LFSR keystream
This is included in the **pylfsr** module.
```python
    from pylfsr import LFSR

    seed = [0, 0, 0, 1, 0]
    fpoly = [3, 2, 1]  # c3=1, c2=1, c1=1
    L = LFSR(fpoly = fpoly, initstate = seed, verbose = True)

    seq = L.runKCycle(num_bits)
```


# Symmetric encryption

## AES256
AES256 is a **block cypher algorithm** with a 32B key, and it can use different modes of operation. The general syntax is:

```python
from cryptography.hazmat.primitives.ciphers \
    import Cipher, algorithms, modes

block_size = 16  # e.g.
key = os.urandom(32)
iv = os.urandom(block_size)  # if needed, depends on mode
nonce = os.urandom(block_size)  # if needed, depends on mode

message = b"A secret message"  # must be binary

cypher = Cypher(algorithms.AES(key), mode = <mode>)

encryptor = cypher.encryptor()
ct = encryptor.update(message) + encryptor.finalize

decryptor = cypher.decryptor()
pt = decryptor.update(ct) + decryptor.finalize
```

### CBC mode
Needs an Initialization Vector.
```python
cypher = Cypher(algorithms.AES(key), modes.CBC(iv))
```

### ECB mode}
Padding is required.
```python
cypher = Cypher(algorithms.AES(key), modes.ECB())
```

### CTR mode
Requires a nonce (unique and never reused). This mode is not reccomended for block cyphers with a block size of less than 128b.
```python
cypher = Cypher(algorithms.AES(key), modes.CTR(nonce))
```

### Effects of modifying ciphertexts in different modes
- **CBC and ECB modes:** The entire block of the altered byte is corrupted.
- **CTR mode:** Only the affected byte is corrupted.

## ChaCha20
ChaCha20 is a **stream cypher algorithm**. It requires a 32B key and a 16B nonce.
```python
nonce = os.urandom(16)

cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)

encryptor = cipher.encryptor()
ct = encryptor.update(message)

decryptor = cipher.decryptor()
pt = decryptor.update(ct)
```


# Assymetric encryption (RSA)

## RSA key generation
```python
from cryptography.hazmat.primitives.asymmetric import rsa

key_size = 2048
public_exponent = 65537

priv_key = rsa.generate_private_key(
    public_exponent,key_size
)

pub_key = priv_key.public_key()
```

We can obtaint the numbers from the key pair:
```python
u = pub_key.public_numbers()
e = u.e
n = u.n

v = priv_key.private_numbers()
p = v.p
q = v.q
d = v.d
```

## PEM serialization
To output the key pair in PEM format:
```python
from cryptography.hazmat.primitives.serialization \
import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import serialization

encoding = serialization.Encoding.PEM

# public key
format = serialization.PublicFormat.SubjectPublicKeyInfo
pem_pub_key = pub_key.public_bytes(encoding, format)

# private key
format = serialization.PrivateFormat.TraditionalOpenSSL

pwd = b"password"  # e.g.
encryption_algorithm = serialization.BestAvailableEncryption(pwd)

pem_priv_key = priv_key.private_bytes(
    encoding, format, encryption_algorithm
)
```

You can deserialize a serialized PEM key with:
```python
pub_key = load_pem_public_key(pem_pub_key)
priv_key = load_pem_private_key(pem_priv_key, pwd)
    
```

## RSA encryption/decryption (with padding)
```python
padder = padding.PKSC1v15()

ct = public_key.encrypt(message, padder)

pt = public_key.decrypt(message, padder)
```

For OAEP padding, we need to set the padder as:
```python
from cryptography.hazmat.primitives import hashes

padder = padding.OAEP(
    mgf = padding.MGF1(
        algorithms.hashes.SHA256()
    ),
    algorithm = hashes.SHA256(),
    label = None
)
```

Note that encrypting the same message won't give the same cyphertext when using PKCS1v15 and OAEP padding, as there is a random bytes string appended.

# Hybrid encryption (RSA OAEP + AES256-CTR)
1. Encrypt the symmetric AES key with the public RSA key and add padding.
    ```python
    encrypted_sym_key = pub_key.encrypt(key, padder)
    ```
2. Generate a nonce.
    ```python
    nonce = os.urandom(block_size)
    ```
3. Encrypt with AES in CTR mode (see [AES256-CTR](#ctr-mode)).

To decrypt: 
1. Decrypt and unpad the AES key with the private RSA key.
    ```python
    key = priv_key.decrypt(encrypted_key, padder)
    ```
2. Decrypt the cyphertext with AES in CTR mode (see [AES256-CTR](#ctr-mode)).


# Key exchange

## AES key wrapping
Key wrapping is encrypting a symmetric key using another symmetric key in order to transmit it through an untrusted channel.

```python
from cryptography.hazmat.primitives.keywrap \
    import aes_key_wrap, aes_key_unwrap

wrapped_key = aes_key_wrap(wrapping_key, key)
key = aes_key_unwrap(wrapping_key, wrapped_key)
```

## Diffie-Hellman
1. Generate the parameters on both parties with the same generator and key size.
```python
from cryptography.hazmat.primitives.asymmetric import dh

parameters = dh.generate_parameters(generator=2, key_size=2048)
```
2. Each party generates their private key
```python
server_priv_key = parameters.generate_private_key()
host_priv_key = parameters.generate_private_key()
```
3. Each party computes their public key and shares it
```python
server_pub_key = parameters.generate_public_key()
host_pub_key = parameters.generate_public_key()
```
4. Each party can now compute the shared key
```python
shared_key = server_priv_key.exchange(host_priv_key.public_key())
shared_key = host_priv_key.exchange(server_priv_key.public_key())
```

# Hash functions

## Message digests (SHA256/SHA512)
```python
from cryptography.hazmat.primitives import hashes

digest = hashes.Hash(hashes.SHA512)
digest.update(message)
digest_value = digest.finalize()
```

Digest values vary widely between similar inputs.


# Key Derivation Functions (KDF)
Two different main goals:
- **Password storage:** conceal the real value of the password and hinder brute-force attacks.
- **Cryptographic key derivation:** increase the quality of a key.

## Scrypt (Secure password storage)
KDF designed for password storage. It needs randomly-generated salt.
```python
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

kdf = Scrypt(
    salt = os.urandom(16),
    length = 32,  # e.g.
    n = 2**14,  # CPU/Mem cost
    r = 8,  # block size
    p = 1  # parallelization
)

key = kdf.derive(password)
```

To verify it:
```python
kdf.verify(password, key)
```

## PBKDF2 (Password-Based KDF 2)
Used for **deriving a cryptographic key from a password**. It needs randomly-generated salt.
```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

kdf = PKDF2HMAC(
    algorithm = hashes.SHA256(),
    length = 32,  # e.g.
    salt = os.urandom(16),
    iterations = 10000  # of the hash algorithm
)

key = kdf.derive(password)
```

To verify it:
```python
kdf.verify(password, key)
```


# Digital Signatures and Authentication

## Hash-Based Authentication Codes (HMAC)
The secret key should be a randomly generated string of bytes, preferably **of equal length to the digest size of the chosen hash function**.  

To compute an authentication tag with HMAC:
```python
from cryptography.hazmat.primitives import hashes, hmac

hmac_key = os.urandom(hashes.SHA256.digest_size)
h = hmac.HMAC(hmac_key, hashes.SHA256())
h.update(message)
signature = h.finalize
```

To verify the authentication tag:
```python
h = hmac.HMAC(hmac_key, hashes.SHA256())
h.update(message)
h_copy = h.copy()
h.verify(signature)
h_copy.verify(incorrect_signature)  # exception
```

## Cipher-Based Authentication Codes (CMAC)
To compute an authentication tag with CMAC:
```python
from cryptography.hazmat.primitives import hashes, cmac

c = cmac.CMAC(algorithms.AES(key))
c.update(message)
signature = c.finalize()
```

To verify the authentication tag:
```python
c = cmac.CMAC(algorithms.AES(key))
c.update(message)
h.verify(signature)
h.verify(incorrect_signature)  # exception
```

## Fernet
A symmetric encryption/decryption system using current best practices which also authenticates the message. Implemented with AES128-CBC and SHA256-HMAC.  

It uses a shared secret key that must be kept secure.
```python
from cryptography.fernet import Fernet

key = Fernet.generate_key()

f = Fernet(key)
token = f.encrypt(message)
pt = f.decrypt(token)
```

## AES-GCM
Implements authenticated encryption with aditional data (AEAD).  

Input consists of:
- **Plaintext:** will be encrypted and authenticated.
- **Associated data:** will only be authenticated.

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(128)
aesgcm = AESGCM(key)
nonce = os.urandom(12)

ct = aesgcm.encrypt(nonce, data, ass_data)
pt = aesgcm.decrypt(nonce, ct, ass_data)
```

## RSA signatures (RSA-PSS)
Use private RSA key to sign, PSS padding (PKCS1v15 is also valid, but not reccomended), and SHA256 hash.
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

signature = priv_key.sign(
    message,
    padding.PSS(mgf = padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)
```
Use the public key to verify the signature:
```python
pub_key.verify(
    signature,
    message,
    padding.PSS(
        mgf = padding.PSS.MAX_LENGTH,
        salt_length = padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

# Certificates (OpenSSL)

## Certificate generation
### Generating a keypair and a self-signed certificate
```bash
openssl req -x509 -newkey rsa:2048 -days 360 -out ac1cert.pem -outform PEM -config .\openssl_AC1.cnf
```

### Printing a certificate
```bash
openssl -x509 -in ac1cert.pem -text -noout
```

### Generating a new key and a certificate signing request
```bash
openssl req -newkew rsa:2048 -days 360 -out ac3req.pem -outform PEM -config openssl_AC2.cnf
```
Note that `-x509` is missing. This request will be sent to AC1 to sign.

### Verifying requests
```bash
openssl req -in .\solicitudes\ac2req.pem -verify -text -noout -config openssl_AC1.cnf
```
AC1 verifies AC2's request.

### Issuing a public key certificate
```bash
openssl ca -in .\solicitudes\ac2req.pem -notext -extensions v3_subca* -config openssl_AC1.cnf  # -extensions usr_cert for users
```
AC2's certificate has been generated by AC1.

## Certificate usage

### Unserializing a PEM certificate
```python
from cryptography import x509

certificate = x509.load_pem_x509_certificate(pemlines)
```
`pemlines` is the `.pem` certificate.

### Retrieving data from certificates
Once serialized, we can access the certificate's:
- `version`
- `serial_number`
- `public_key()`
- `not_valid_before`, `not_valid_after`
- `issuer`
- `signature_hash_algorithm`
- `signature`
- `tbs_certificate_bytes`
- ...

### Verifying the signature in a certificate
```python
from cryptography import x509
from cryptography.hazmat.primitives import padding

pub_key_AC2 = x509.load_pem_x509_certificate(pem_pub_key_AC2)
certificate_C = x509.load_pem_x509_certificate(pem_certificate_C)

pub_key_AC2.verify(
    certificate_C.signature,
    certificate_C.tbs_certificate_bytes,
    padding.PKCS1v15(),  # depends on the padding used to create it
    certificate_C.signature_hash_algorithm
)
```
This verifies that C's certificate has indeed been signed and issued by AC2.  

**Note:** Creating a key pair requires creating a PEEM passphrase. This passphrase is used when issuing a certificate.