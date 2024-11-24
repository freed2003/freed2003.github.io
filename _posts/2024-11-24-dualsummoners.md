---
layout: post
title: SECCON Quals 2024 Dual Summoners
date: 2024-11-23 15:09:00
description: Nonce means only used once
tags: crypto
categories: ctf-writeups
featured: true
---

The two summoners in the name refer to two instances of AES-GCM, each with a different key. The interesting thing here is that they both use the same nonce, which is clearly an issue since the word nonce means "number only used once". The code we are given is the following

```python
from Crypto.Cipher import AES
import secrets
import os
import signal

signal.alarm(300)

flag = os.getenv('flag', "SECCON{sample}")

keys = [secrets.token_bytes(16) for _ in range(2)]
nonce = secrets.token_bytes(16)

def summon(number, plaintext):
    assert len(plaintext) == 16
    aes = AES.new(key=keys[number-1], mode=AES.MODE_GCM, nonce=nonce)
    ct, tag = aes.encrypt_and_digest(plaintext)
    return ct, tag

# When you can exec dual_summon, you will win
def dual_summon(plaintext):
    assert len(plaintext) == 16
    aes1 = AES.new(key=keys[0], mode=AES.MODE_GCM, nonce=nonce)
    aes2 = AES.new(key=keys[1], mode=AES.MODE_GCM, nonce=nonce)
    ct1, tag1 = aes1.encrypt_and_digest(plaintext)
    ct2, tag2 = aes2.encrypt_and_digest(plaintext)
    # When using dual_summon you have to match tags
    assert tag1 == tag2

print("Welcome to summoning circle. Can you dual summon?")
for _ in range(10):
    mode = int(input("[1] summon, [2] dual summon >"))
    if mode == 1:
        number = int(input("summon number (1 or 2) >"))
        name   = bytes.fromhex(input("name of sacrifice (hex) >"))
        ct, tag = summon(number, name)
        print(f"monster name = [---filtered---]")
        print(f"tag(hex) = {tag.hex()}")

    if mode == 2:
        name   = bytes.fromhex(input("name of sacrifice (hex) >"))
        dual_summon(name)
        print("Wow! you could exec dual_summon! you are master of summoner!")
        print(flag)

```

So we are also given an encrypt oracle, except that instead of returning the ciphertext it returns the computed tag from the AES object of our choice, either `aes1` or `aes2`. We get the flag if we can find an input such that the two ciphers return the same MAC.

AES-GCM works in the field $$GF(2^128)$$ with polynomial $$x^{128} + x^7+x^2+x+1$$, so all further expressions will be implied to be in this field. Now how do we actually find the desired input, first let's look at how the tag is computed. Let 

$$
c = c_1|c_2|c_3|\dots |c_n
$$

be the ciphertext where $$c_i$$ refers to the ith block out of $$n$$. Now let $$H = enc_k(0)$$ be the encryption of the zero block using AES with the encryption key and $$s = enc_k(IV)$$ be the encryption of the nonce. The tag can be computed as

$$
t = H^{n+2}\cdot a + H^{n+1}\cdot c_1 + H^{n}\cdot c_2 +\dots H^2\cdot c_n + H\cdot L + s
$$

where $$a$$ is the authentication data and $$L$$ is the encoding 
$$len(a)||len(c)$$ with $$len(x)$$ is the number of bits in $$x$$ as a 64 bit unsigned integer. This may seem like a lot of terms to keep track of, but we'll soon see that we can ignore many of these.

First, the script uses no authentication data, so we can ignore that term. Also, the oracle actually restricts us to one block exactly, so we set $$n=1$$. Our equation now becomes

$$
t = H^2\cdot c_1 + H\cdot 128 + s
$$

Great, we see the the tag is computed through a simple equation. The only issue is that this polynomial is based on the ciphertext, but our input is the plaintext. Fortunately, the plaintext and ciphertext in AES-GCM have a very simple relationship. We won't go into depth for the encryption since it is not the focuse of the challenge, but essentially you encrypt a counter, which is determined by the IV, with the key and then xor the result with the plaintext. Since the IV doesn't change, the counter's encryption doesn't change so we can just let it be some constant $$m$$.

$$
t = H^2\cdot c_1 + H\cdot 128 + s = H^2\cdot (p_1 + m) + H\cdot 128 + s = H^2\cdot p_1 + H^2\cdot m + H\cdot 128 + s
$$

We can now think of this as a function in $$p_1$$.

To disambiguate between the two ciphers, we will let $$k_1$$ be the key for `aes1` and $$k_2$$ the key for `aes2`. We label $$H$$, $$m$$ and $$s$$ similarly to get

$$
t_1(p) = H_1^2\cdot p + H_1^2\cdot m_1 + H_1\cdot 128 + s_1
$$

$$
t_2(p) = H_2^2\cdot p + H_2^2\cdot m_2 + H_2\cdot 128 + s_2
$$

where $$p$$ is the input plaintext and the RHS is what is returned as the tag. These functions simulate the oracle we are given, so let's see how we can use them. Setting the two equal to eachother gives us

$$
H_1^2\cdot p + H_1^2\cdot m_1 + H_1\cdot 128 + s_1 = H_2^2\cdot p + H_2^2\cdot m_2 + H_2\cdot 128 + s_2
$$

$$
H_1^2\cdot p - H_2^2\cdot p =  H_2^2\cdot m_2 + H_2\cdot 128 + s_2 - H_1^2\cdot m_1 + H_1\cdot 128 + s_1
$$

$$
p = \frac{H_2^2\cdot m_2 + H_2\cdot 128 + s_2 - H_1^2\cdot m_1 + H_1\cdot 128 + s_1}{H_1^2- H_2^2}
$$

We now have an expression for our desired input. We have

$$
t_1(0) = H_1^2\cdot m_1 + H_1\cdot 128 + s_1
$$

$$
t_1(1) = H_1^2 + H_1^2\cdot m_1 + H_1\cdot 128 + s_1
$$

So we can add these two to get $$H_1^2$$ (remember addition and subtraction are the same in a field with characteristic $$2$$). We repeat the processes to get $$H_2^2$$. We substitute these equations into our expression for $$p$$ to get

$$
p = \frac{t_2(0) + t_1(0)}{H_1^2 - H_2^2}
$$

Since we have all the terms on the right hand side, we can easily compute $$p$$. We can now just submit it and we get the flag `SECCON{Congratulation!_you are_master_of_summonor!_you_can_summon_2_monsters_in_one_turn}`. The solve script follows

```python
from pwn import *
def flip(a):
   return int(bin(a)[2:].zfill(128)[::-1], 2)
def gf2_128_mult(x, y):
    assert x < (1 << 128)
    assert y < (1 << 128)
    res = 0
    for i in range(127, -1, -1):
        res ^= x * ((y >> i) & 1)  # branchless
        x = (x >> 1) ^ ((x & 1) * 0xE1000000000000000000000000000000)
    assert res < 1 << 128
    return res

def gf_degree(a) :
  res = 0
  a >>= 1
  while (a != 0) :
    a >>= 1;
    res += 1;
  return res

def gf_invert(a, mod=340282366920938463463374607431768211591) :
  v = mod
  g1 = 1
  g2 = 0
  j = gf_degree(a) - 128

  while (a != 1) :
    if (j < 0) :
      a, v = v, a
      g1, g2 = g2, g1
      j = -j

    a ^= v << j
    g1 ^= g2 << j

    a %= 2**128  # Emulating 8-bit overflow
    g1 %= 2**128 # Emulating 8-bit overflow

    j = gf_degree(a) - gf_degree(v)

  return g1
def get_inverse(a):
   f = flip(a)
   inv = gf_invert(f)
   back = flip(inv)
   return back
aid = b"0"*32
mid = b"80"+b"0"*30
print(gf2_128_mult(2, 1 << 127))
conn = remote("dual-summon.seccon.games", 2222)

print(conn.recvline().decode())

print(conn.recvuntil(b">").decode())
conn.sendline(b"1")
print(conn.recvuntil(b">").decode())
conn.sendline(b"1")
print(conn.recvuntil(b">").decode())
conn.sendline(aid)
print(conn.recvline().decode())
tag1 = conn.recvline().decode().split(" = ")[1]
print(tag1)


print(conn.recvuntil(b">").decode())
conn.sendline(b"1")
print(conn.recvuntil(b">").decode())
conn.sendline(b"1")
print(conn.recvuntil(b">").decode())
conn.sendline(mid)
print(conn.recvline().decode())
tag2 = conn.recvline().decode().split(" = ")[1]
print(tag2)

print(conn.recvuntil(b">").decode())
conn.sendline(b"1")
print(conn.recvuntil(b">").decode())
conn.sendline(b"2")
print(conn.recvuntil(b">").decode())
conn.sendline(aid)
print(conn.recvline().decode())
tag3 = conn.recvline().decode().split(" = ")[1]
print(tag3)

print(conn.recvuntil(b">").decode())
conn.sendline(b"1")
print(conn.recvuntil(b">").decode())
conn.sendline(b"2")
print(conn.recvuntil(b">").decode())
conn.sendline(mid)
print(conn.recvline().decode())
tag4 = conn.recvline().decode().split(" = ")[1]
print(tag4)

H12 = int(tag2, 16) ^ int(tag1, 16)

H22 = int(tag4, 16) ^ int(tag3, 16)

target = int(tag1, 16) ^ int(tag3, 16)

inv = get_inverse(H12 ^ H22)

ta = gf2_128_mult(target, inv)
ans = hex(int(bin(ta)[2:].zfill(128),2))[2:]

print(conn.recvuntil(b">").decode())
conn.sendline(b"2")
print(conn.recvuntil(b">").decode())
conn.sendline(ans.encode())
conn.recvline()
print(conn.recvline())
```