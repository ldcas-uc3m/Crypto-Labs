# Converting data

## Binary to hexadecimal
Use python built-in functions.
```python
bin_data = b"data"
hex_data = bin_data.hex()
bin_data = bytes.fromhex(hex_data)
```

## Binary to base 64
Use python module `base64`.
```python
import base64

bin_data = b"data"
b64_data = base64.b64encode(bin_data)
bin_data = base64.b64decode(b64_data)
```

# Randomization
## Random keystream
You can generate a random string of bytes by using an OS function, or a specialized library, `secrets`.

```python
import os

rand = os.urandom(num_bytes)
```

```python
import secrets

rand = secrets.token_bytes(num_bytes)
```

## LFSR keystream
```python
from pylfsr import LFSR
```
```python
seed = [0, 0, 0, 1, 0]
fpoly = [3, 2, 1]  # c3=1, c2=1, c1=1
L = LFSR(fpoly = fpoly, initstate = seed, verbose = True)

seq = L.runKCycle(num_bits)
```


# Message digests (Hash functions) - SHA512
Takes an arbitrary size block of data and calculates a 64B (512b) bit string.  
Digest values vary widely between similar inputs.  
```python
from cryptography.hazmat.primitives import hashes
```
```python
digest = hashes.Hash(hashes.SHA512())
digest.update(message)
digest_value = digest.finalize()
```

**Note:** Every time you need to compute a digest you need to create a `hash` object.


# Padding
The order of operation must always be:
1. Pad data
2. Encrypt padded data
3. Exchange data
4. Decrypt encrypted data
5. Unpad plaintext

## Symmetric padding - PKCS7
Some **block cyphers** might require padding if the message is not a multiple of the block size. 

```python
from cryptography.hazmat.primitives import padding
```
```python
padder = padding.PKCS7(BLOCK_SIZE * 8).padder()  # the padding is specified in bits
padded_data = padder.update(data) + padder.finalize()

unpadder = padding.PKCS7(BLOCK_SIZE * 8).unpadder()
data = unpadder.update(padded_data) + unpadder.finalize()
```

## Asymmetric padding (for RSA)
Asymmetric padding is done not only because of the length of the message, but more importantly, because the security.

### PKCS1v15 padding
Used for **RSA signing and encryption**, but **not reccomended** for either (prefer [OAEP](#oaep-padding-asymmetric) for encryption and [PSS](#pss-padding-asymmetric) for signing).
```python
from cryptography.hazmat.primitives import padding
```
```python
padder = padding.PKCS1v15()
```


### OAEP-SHA256 padding
Used for **RSA encryption** (but not signing), and the **recommended method** to do so, as is has been proven secure.
```python
from cryptography.hazmat.primitives import padding, hashes
```
```python
padder = padding.OAEP(
    mgf = padding.MGF1(utils.hashes.SHA256()),
    algorithm = utils.hashes.SHA256(),
    label = None
)
```

### PSS-SHA256 padding
Used for **RSA signing** (but not encryption), and the **recommended method** to do so, as is has been proven secure.
```python
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
```
```python
padder = asym_padding.PSS(
    mgf = asym_padding.MGF1(hashes.SHA256()),
    salt_length = asym_padding.PSS.MAX_LENGTH
)
```


# Symmetric encryption
The general syntax is:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
```
```python
key = os.urandom(KEY_SIZE)
iv = os.urandom(BLOCK_SIZE)  # if needed
nonce = os.urandom(BLOCK_SIZE)  # if needed

message = b"A secret message"  # must be binary

cipher = Cipher(algorithm, mode)

# encrypt
encryptor = cyiher.encryptor()
ct = encryptor.update(message) + encryptor.finalize()

# decrypt
decryptor = cipher.decryptor()
pt = decryptor.update(ct) + decryptor.finalize()
```

## AES-256
AES-256 is a **block cypher algorithm** with a **32B key**, and **16B block size**. It can use different modes of operation. 

```python
KEY_SIZE = 32  # Bytes
BLOCK_SIZE = 16  # Bytes
```
```python
cipher = Cipher(algorithms.AES256(key), mode = <mode>)
```


## Camellia-256
It's a **block cypher** (with comparable security and performance to AES, but used) with **32B keys**.
```python
KEY_SIZE = 32  # Bytes
```
```python
cipher = Cipher(algorithms.Camellia(key), mode = <mode>)
```

## Block cipher modes
Block ciphers have different execution modes:

### CBC mode
Needs an Initialization Vector (16B, same as the block size), and padding.
```python
cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
```

### ECB mode
Padding is required.
```python
cipher = Cipher(algorithms.AES256(key), modes.ECB())
```

### CTR mode
Requires a nonce (unique and never reused). This mode is not reccomended for block cyphers with a block size of less than 16B.
```python
cipher = Cipher(algorithms.AES256(key), modes.CTR(nonce))
```

### Effects of modifying ciphertexts in different modes
- **CBC and ECB modes:** The entire block of the altered byte is corrupted.
- **CTR mode:** Only the affected byte is corrupted.


## ChaCha20
ChaCha20 is a **stream cipher algorithm**. It requires a **32B key** and a **16B nonce**.
```python
KEY_SIZE = 32  # Bytes
BLOCK_SIZE = 16  # Bytes
```
```python
cipher = Cipher(algorithms.ChaCha20(key, nonce), mode = None)
```


# Assymetric encryption - RSA-2048
RSA-2048 uses a **2048b key**, and we'll use the public exponent as default (more info of why [here](https://www.youtube.com/watch?v=cbGB__V8MNk)). It **requires padding**.
```python
KEY_SIZE = 2048  # bits
PUBLIC_EXPONENT = 65537
```

## RSA key generation
```python
from cryptography.hazmat.primitives.asymmetric import rsa
```
```python
priv_key = rsa.generate_private_key(PUBLIC_EXPONENT, KEY_SIZE)
pub_key = priv_key.public_key()
```

We can obtaint the numbers from the key pair:
```python
u = pub_key.public_numbers()
e = u.e
n = u.n

v = priv_key.private_numbers()
d = v.d
p = v.p
q = v.q
```

## PEM serialization
To output the key pair in PEM format:
```python
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import serialization
```
```python
encoding = serialization.Encoding.PEM

# public key
format = serialization.PublicFormat.SubjectPublicKeyInfo

pem_pub_key = pub_key.public_bytes(encoding, format)

# private key
pwd = b"password"  # must be in Bytes

format = serialization.PrivateFormat.TraditionalOpenSSL
encryption_algorithm = serialization.BestAvailableEncryption(pwd)

pem_priv_key = priv_key.private_bytes(encoding, format, encryption_algorithm)
```

You can deserialize a serialized PEM key with:
```python
pub_key = load_pem_public_key(pem_pub_key)
priv_key = load_pem_private_key(pem_priv_key, pwd)
```

## RSA encryption/decryption (with padding)
Use the preferred asymmetric `padder`, either [PKCS1v15](#pkcs1v15-padding-asymmetric) (RSA-PKCS1v15) or [OAEP](#oaep-padding-asymmetric) (RSA-OAEP).
```python
# padder = padding.<padder>()

ct = pub_key.encrypt(message, padder)  # public key of receiver
pt = priv_key.decrypt(ct, padder)  # private key of receiver
```

Note that encrypting the same message won't give the same cyphertext when using PKCS1v15 and OAEP padding, as there is a random bytes string appended.  

Also note that you can't encrypt the same message twice, as the ciphertext resulting from the first encryption is too long for the second encryption.  
The maximum message length with RSA2048-PKC1v15 is 246B, while with RSA2048-OAEP-SHA256 it's 191B.


# Hybrid encryption - RSA-OAEP + AES256-CTR
To encrypt:
1. Encrypt the symmetric AES key with the public RSA key and add [OAEP padding](#oaep-padding-asymmetric).
    ```python
    padder = padding.OAEP(mgf = padding.MGF1(algorithms.hashes.SHA256()), algorithm = hashes.SHA256(), label = None)
    encrypted_sym_key = pub_key.encrypt(key, padder)
    ```
2. Generate a nonce.
    ```python
    nonce = os.urandom(BLOCK_SIZE)
    ```
3. Encrypt with [AES-256](#aes-256) in [CTR mode](#ctr-mode).

To decrypt: 
1. Decrypt and unpad the AES key with the private RSA key.
    ```python
    key = priv_key.decrypt(encrypted_key, padder)
    ```
2. Decrypt the cyphertext with [AES-256](#aes-256) in [CTR mode](#ctr-mode).


# Key exchange

## AES Key wrapping (symmetric)
You can use a symmetric key to wrap another symmetric key, in order to securely store the first one or transmit it over an untrusted channel.
```python
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
```
```python
# wrapping
wrapped_key = aes_key_wrap(wrapping_key, key)

# unwrapping
unwrapped_key = aes_key_unwrap(wrapping_key, wrapped_key)
```

## Diffie-Hellman (asymmetric)
It's used to establish a **non-authenticated** shared key through an untrusted channel, but it's computationaly costly (slow).
For this implementation, we'll use the generator `2` and a key size of 2048b.
```python
GENERATOR = 2  # or 5
KEY_SIZE = 2048  # bits
```
1. Generate the parameters on both parties with the same generator and key size.
    ```python
    from cryptography.hazmat.primitives.asymmetric import dh
    ```
    ```python
    parameters = dh.generate_parameters(GENERATOR, KEY_SIZE)
    ```
2. Each party generates their private key.
    ```python
    server_priv_key = parameters.generate_private_key()
    host_priv_key = parameters.generate_private_key()
    ```
3. Each party computes their public key and shares it.
    ```python
    server_pub_key = server_priv_key.public_key()
    host_pub_key = host_priv_key.public_key()
    ```
4. Each party can now compute the shared key.
    ```python
    shared_key = server_priv_key.exchange(host_pub_key)
    shared_key = host_priv_key.exchange(server_pub_key)
    ```


# Message Authentication Codes (symmetric)

## Hash-Based Authentication Codes (HMAC)
The **length of the MAC is the length of the hash used**, e.g. with SHA256, the length is 32B.  
The **secret key** should be a randomly generated string of bytes, **of equal length to the digest size of the chosen hash function**.  

To compute an authentication tag with HMAC:
```python
from cryptography.hazmat.primitives import hashes, hmac
```
```python
hmac_key = os.urandom(hashes.SHA256.digest_size)
h = hmac.HMAC(hmac_key, hashes.SHA256())
h.update(message)
auth_tag = h.finalize
```

To verify the authentication tag:
```python
h = hmac.HMAC(hmac_key, hashes.SHA256())
try:
    h.update(message)
    h.verify(auth_tag)
    # the verification worked
except InvalidSignature:
    # the verification failed
```

## Cipher-Based Authentication Codes (CMAC)
The **length of the MAC is the length of the algorithm key length used**, e.g. with AES128, the length is 16B.  
The **secret key** should be a randomly generated string of bytes, **of equal length to the key size of the chosen algorithm**.  

To compute an authentication tag with CMAC:
```python
from cryptography.hazmat.primitives import algorithms, cmac
```
```python
cmac_key = os.urandom(algorithms.AES128.key_size)
c = cmac.CMAC(algorithms.AES128(cmac_key))
c.update(message)
signature = c.finalize()
```

To verify the authentication tag:
```python
c = cmac.CMAC(algorithms.AES128(cmac_key))
try:
    c.update(message)
    c.verify(auth_tag)
    # the verification worked
except InvalidSignature:
    # the verification failed
```


# Key Derivation Functions (KDF)
Two different main goals:
- **Password storage:** conceal the real value of the password and hinder brute-force attacks.
- **Cryptographic key derivation:** increase the quality of a key.

## Scrypt (Secure password storage)
KDF designed for password storage. It needs a **16B randomly-generated salt**.
```python
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
```
```python
salt = os.urandom(16)
kdf = Scrypt(
    salt = salt,
    length = 32,  # of the derived key
    n = 2**14,  # CPU/Mem cost
    r = 8,  # block size
    p = 1  # parallelization
)

key = kdf.derive(password)
```

To verify it:
```python
try:
    kdf = Scrypt(salt = salt, length = 32, n = 2**14, r = 8, p = 1)
    kdf.verify(password, key)
    # verification passed
except InvalidKey:
    # verification failed
```

**Note:** You can't reuse KDFs.


## PBKDF2 (Password-Based KDF 2)
Used for **deriving a cryptographic key from a password**. It needs a **16B randomly-generated salt**.
```python
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
```
```python
salt = os.urandom(16)
kdf = PKDF2HMAC(
    algorithm = hashes.SHA256(),
    length = 32,  # of the desired key
    salt = salt,
    iterations = 10000  # of the hash algorithm
)

key = kdf.derive(password)
```

To verify it (although it's not necessary if used for generating higher quality keys):
```python
try:
    kdf = PKDF2HMAC(algorithm = hashes.SHA256(), length = 32, salt = os.urandom(16), iterations = 10000)
    kdf.verify(password, key)
    # verification passed
except InvalidKey:
    # verification failed
```


# Authenticated Encryption (symmetric)

## Fernet
A symmetric encryption/decryption system using current best practices which also authenticates the message.  
Implemented with AES128-CBC and SHA256-HMAC.  

It uses a shared secret key **in base64** that must be kept secure.  

Tokens generated with the same key are similar, but different, as the IVs vary.  
The token contains the HMAC authentication tag, several parameters (version, timestamp), the IV for CBC and the AES ciphertext.

You can encrypt with:
```python
from cryptography.fernet import Fernet
```
```python
key = Fernet.generate_key()

f = Fernet(key)

token = f.encrypt(message)
```

Decryption also verifies the authenticity of the message:
```python
try:
    pt = f.decrypt(token)
    # verification successful
except InvalidToken:
    # verification failed
```


## AES-GCM
Implements authenticated encryption with aditional data (AEAD).  

Input consists of:
- **Plaintext:** will be encrypted and authenticated.
- **Associated data:** will only be authenticated.

Needs a nonce, but **never reuse a nonce with the same key**.

You can encrypt with:
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
```
```python
key = AESGCM.generate_key(128)
nonce = os.urandom(12)

aesgcm = AESGCM(key)

ct = aesgcm.encrypt(nonce, data, ass_data)
```

Decryption also verifies the authenticity of the message:
```python
try:
    pt = aesgcm.decrypt(aesgcm_nonce, corrupted_tag, aad)
    # verification successful
except InvalidTag:
    # verification failed
```


# RSA signatures - RSA-PSS-SHA256
Use private RSA key to sign, PSS padding (PKCS1v15 is also valid, but not reccomended), and SHA256 hash.
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as assym_padding
```
```python
signature = priv_key.sign(
    message,
    assym_padding.PSS(
        mgf = assym_padding.MGF1(hashes.SHA256()),
        salt_length = assym_padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```
Use the public key to verify the signature:
```python
try:
    pub_key.verify(
        signature,
        message,
        assym_padding.PSS(
            mgf = assym_padding.MGF1(hashes.SHA256()),
            salt_length = assym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # verification successful
except InvalidSignature:
    # verification failed
```

# Certificates - OpenSSL

## Generating a keypair and a self-signed certificate
```bash
openssl req -x509 -newkey rsa:2048 -days 360 -out <ca_cert>.pem -outform PEM -config <ca_config>.cnf
```

## Printing a certificate
```bash
openssl -x509 -in <ca_cert>.pem -text -noout
```

## Generating a certificate signing request (CSR)
```python
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # Provide various details about who we are.
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Madrid"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Alcorcón"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Acsr"),
])).sign(load_pem_private_key(pem_priv_key, PASSWORD), hashes.SHA256())  # Sign the CSR with our private key
```
You can then encode it in PEM format with:
```python
csr.public_bytes(serialization.Encoding.PEM)
```
If you save it in the corresponding certificate requests folder, you can check its contents with:
```bash
openssl req -in <ca-requests-folder>/<usr_csr>.pem -text -noout
```

## Verifying requests
```bash
openssl req -in <ca-requests-folder>/<usr_csr>.pem -verify -text -noout -config <ca_config>.cnf
```

## Issuing a public key certificate for an user
```bash
openssl ca -in <ca-requests-folder>/<usr_csr>.pem  -extensions usr_cert -notext -config <ca_config>.cnf
```

## Exporting a user certificate and and its certification chain
```bash
openssl pkcs12 -export -in <usr_cert>.pem -inkey <usr_key>.pem -certfile <ca_cert>.pem -out Acert_with_sk.p12
```

## Retrieving data from certificates
You can deserialize a PEM certificate with:
```python
certificate = load_pem_x509_certificate(cert_pem)
```
Once deserialized, we can access the certificate's:
- `version`
- `serial_number`
- `public_key()`
- `not_valid_before`, `not_valid_after`
- `issuer`
- `signature_hash_algorithm`
- `signature`
- `tbs_certificate_bytes`