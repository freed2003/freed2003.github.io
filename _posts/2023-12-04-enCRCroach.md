---
layout: post
title: SquareCTF 2023 enCRCroach
date: 2023-10-03 15:09:00
description: Why webdevelopers should learn cryptorgraphy
tags: crypto
categories: ctf-writeups
featured: true
---

We're given the source code to a server where we are supposed to impersonate admin. Validation is done by a token that is encrypted with AES-CTR. Basically, the server decrypts the token and checks the name of the user and if it's admin then they spit out the flag. here's the code.
```python
import hashlib
import os
import secrets

import fastcrc
import werkzeug.security
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, Response, request, send_from_directory

app = Flask(__name__)

SERVER_KEY = bytes.fromhex(os.environ.get("SERVER_KEY", ""))
IV_LEN = 16
# USER_LEN = can potentially vary
NONCE_LEN = 42
MAC_LEN = 8
KEY_LEN = 32

USER_DB = {
    # Someone keeps hacking us and reading out the admin's /flag.txt.
    # Disabling this account to see if that helps.
    # "admin": "7a2f445babffa758471e3341a1fadce9abeff194aded071e4fd48b25add856a7",

    # Other accounts. File a ticket similar to QDB-244321 to add or modify passwords.
    "azure": "9631758175d2f048db1964727ad2efef4233099b97f383e4f1e121c900f3e722",
    "cthon": "980809b1482352ae59be5d3ede484c0835b46985309a04ac1bad70b22a167670",
}


def response(text, status=200):
    return Response(text, status=status, mimetype="text/plain")


@app.route("/", methods=["GET", ])
def root():
    return response("""Endpoints:
  - /auth?user=<user>: Auth a user with an optional password. Returns an auth token.
  - /read/<path>?token=<token>: Read out a file from a user's directory. Token required.
""")


@app.route("/auth", methods=["GET", ])
def auth():
    """Return a token once the user is successfully authenticated.
    """
    user = request.args.get("user")
    password = request.args.get("password", "")
    if not user or user not in USER_DB:
        return response("Bad or missing 'user'", 400)

    password_hash = USER_DB[user]
    given = hashlib.pbkdf2_hmac("SHA256", password.encode(), user.encode(), 1000).hex()
    if password_hash != given:
        return response("Bad 'password'", 400)

    # User is authenticated! Return a super strong token.
    return response(encrypt_token(user, SERVER_KEY).hex())


@app.route("/read", defaults={"path": None})
@app.route("/read/<path>", methods=["GET", ])
def read(path: str):
    """Read a static file under the user's directory.

    Lists contents if no path is provided.

    Decrypts the token to auth the request and get the user's name.
    """
    try:
        user = decrypt_token(bytes.fromhex(request.args.get("token", "")), SERVER_KEY)
    except ValueError:
        user = None

    if not user:
        return response("Bad or missing token", 400)

    user_dir = werkzeug.security.safe_join("users", user)

    if path is None:
        listing = "\n".join(sorted(os.listdir(os.path.join(app.root_path, user_dir))))
        return response(listing)

    return send_from_directory(user_dir, path)


def encrypt_token(user: str, key: bytes) -> bytes:
    """Encrypt the user string using "authenticated encryption".

    JWTs and JWEs scare me. Too many CVEs! I think I can do better...

    Here's the token format we use to encrypt and authenticate a user's name.
    This is sent to/from the server in ascii-hex:
      len :  16    variable      42      8
      data:  IV ||   USER   || NONCE || MAC
                  '------------------------' Encrypted
    """
    assert len(key) == KEY_LEN

    user_bytes = user.encode("utf-8")

    iv = secrets.token_bytes(IV_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()

    mac = gen_mac(iv + user_bytes + nonce)

    ciphertext = cipher.update(user_bytes + nonce + mac) + cipher.finalize()

    return iv + ciphertext


def decrypt_token(token: bytes, key: bytes) -> [None, str]:
    assert len(key) == KEY_LEN

    iv, ciphertext = splitup(token, IV_LEN)
    if not iv or not ciphertext:
        return None

    cipher = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    plaintext = cipher.update(ciphertext) + cipher.finalize()

    user_bytes, nonce, mac = splitup(plaintext, -(NONCE_LEN + MAC_LEN), -MAC_LEN)
    if not user_bytes or len(nonce) != NONCE_LEN or len(mac) != MAC_LEN:
        return None

    computed = gen_mac(iv + user_bytes + nonce)
    if computed != mac:
        return None

    return user_bytes.decode("utf-8")


def gen_mac(data: bytes) -> bytes:
    # A 64-bit CRC should be pretty good. Faster than a hash, and can't be brute forced.
    crc = fastcrc.crc64.go_iso(data)
    return int.to_bytes(crc, length=MAC_LEN, byteorder="big")


def splitup(data: bytes, *indices):
    last_index = 0
    for index in indices:
        yield data[last_index:index]
        last_index = index
    yield data[last_index:]


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=os.environ.get("FLASK_SERVER_PORT"), debug=False)
```

Ok that's a lot. The first main thing to look at is the encrypt and decrypt token functions. They do what they say, basically they encrypt a token of the user's name and add the information needed to decrypt it (other than the key of course). They also add a mac to try to defend against attacks that modify the cipher text, but the mac is using CRC and we'll later see that CRC doesn't make for a good mac. 

So if you don't know what CTR mode does, it basically encrypts some value with AES and then XORs the resulting value with your plaintext to produce the cipher text. It's basically turning AES into a stream cipher. Here's a picture to help better understand it

![image](https://hackmd.io/_uploads/r1h4O1hB6.png)

Decryption is very similar. You take the nonce and increment it and xor the result with the ciphertext to get the plaintext, since xoring something with itself yields $$0$$. If you don't see it already, this is actually very susceptible to a known plaintext attack where if we know the plaintext then we can modify the ciphertext to decrypt whatever we want even if we don't know the key. To see this, consider an arbitrary byte in the plaintext. It encrypts to the form

$$ct_i = pt_i \oplus enc_k(nonce + ctr)_i$$

And the decryption works as following

$$ct_i \oplus enc_k(nonce + ctr)_i = pt_i \oplus enc_k(nonce + ctr)_i \oplus enc_k(nonce + ctr)_i = pt_i$$

where $$i$$ denote's it's index in the block. If we know the value of $$pt_i$$ then we can xor the ciphertext byte with $$pt_i \oplus a$$ for any value of $$a$$. Decrypting this new value gives us

$$ct_i\oplus pt_i \oplus a \oplus enc_k(nonce + ctr)_i = pt_i pt_i \oplus a \oplus enc_k(nonce + ctr)_i \oplus enc_k(nonce + ctr)_i = a$$

and we have successfully modified our ciphertext to produce an arbitrary byte $$a$$ upon decryption.

Why is this useful for our challenge? Well, they disabled the ability to get a token with user "admin" but we can still get a token with the user "cthon" or "azure". Even though the user name gets encrypted, we are given the position in the ciphertext so we can use our attack to change it to read "admin" instead. Should be simple enough.

So now all we need is to get a token. This requires logging into the one of the enabled accounts. The information for these accounts is located in the code here

```python
USER_DB = {
    # Someone keeps hacking us and reading out the admin's /flag.txt.
    # Disabling this account to see if that helps.
    # "admin": "7a2f445babffa758471e3341a1fadce9abeff194aded071e4fd48b25add856a7",

    # Other accounts. File a ticket similar to QDB-244321 to add or modify passwords.
    "azure": "9631758175d2f048db1964727ad2efef4233099b97f383e4f1e121c900f3e722",
    "cthon": "980809b1482352ae59be5d3ede484c0835b46985309a04ac1bad70b22a167670",
}
```

The value for each key is the hash of the password, so we can't actually get the password directly from here. We can see the process in the code here.
```python
 password_hash = USER_DB[user]
    given = hashlib.pbkdf2_hmac("SHA256", password.encode(), user.encode(), 1000).hex()
    if password_hash != given:
        return response("Bad 'password'", 400)
```
So it's hashing the password with pbkdf2_hmac sha256 with the salt of the user and 1000 rounds. Running hashcat with rockyou.txt will tell us the password is "******", which is a funny password. I'm going to leave the exact details of running hashcat out of here since it's not important, but basically you can give hashcat a dictionary, a target and the hashing method and it will bash it out for you.

Ok, so now we input it into the website and get a token. We can use our known plaintext attack to retrieve a new token the decrypts to user "admin" and submit that. Except we forgot one thing, the CRC check on the ciphertext to check for modifications. The thing is, CRC isn't really secure since it follows the following linear property. 

$$CRC(a) \oplus CRC(b) \oplus CRC(c) = CRC(a\oplus b\oplus c)$$

for messages $$a,b,c$$ that have equal length to eachother. (I won't prove this here but I'm sure you can find something online). Ok, so using this we can calculate our new CRC. How exactly do we do this? So first let $$a$$ be our original unmodified token. Remember that we modified it by xoring by another value, so that value can be $$b$$. But wait! $$b$$ was only of length $$5$$ since we were just changing "cthon" to "admin" right? That's much shorter than the length of $$a$$. It is, so what we do is pad out the rest of the bytes that are unmodified with null bytes since xoring by a nullbyte gives the same value back. Finally, we set $$c$$ equal to all nullbytes with equal length with $$a$$ and $$b$$. $$a\oplus b\oplus c$$ is now equal to what we want, so we can find the new CRC.

We submit this to the server, which gives us the flag. Here's the solve script to get the new token

```python
import hashlib
import os
import secrets

import fastcrc
import werkzeug.security
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
IV_LEN = 16
ct = "eb5ce85fc4b88e8e993170343a602e67d9b928b33d82346584ab3a504f8bf58d59687fcb46ded50c5af5fc55a7d6f5a38cfd07f0fcb040ccb2574ca59a05cc1aef938aa84ff6d0"
MAC_LEN = 8
def gen_mac(data: bytes) -> bytes:
    # A 64-bit CRC should be pretty good. Faster than a hash, and can't be brute forced.
    crc = fastcrc.crc64.go_iso(data)
    return int.to_bytes(crc, length=MAC_LEN, byteorder="big")
ct = bytes.fromhex(ct)
iv = ct[:16]
mac = ct[-8:]
nonce = ct[-50:-8]
pt = bytearray(ct[16:-50])
target = b"admin"
k = b"cthon"
yea = []
for i in range(5):
    yea.append(target[i] ^ k[i])
    pt[i] = pt[i] ^ k[i] ^ target[i]
aa = bytes(yea)

token = iv + pt + nonce
org = b"\x00" * 16 + b"cthon" + b"\x00" *42
dd = b"\x00" * 16 + aa + b"\x00"*42
mac3 = gen_mac(bytes(63))
mac2 = gen_mac(dd)
newmac = bytes([i ^ j ^ k for i,j,k in zip(mac,mac2,mac3)])

final = token + newmac
print(final.hex())
```

where the initial variable $$ct$$ is the token we are modifying.