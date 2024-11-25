---
layout: post
title: Buckeye 2023 Twin Prime
date: 2023-10-03 15:09:00
description: "You know what's not one of a kind? A twin!"
tags: crypto
categories: ctf-writeups
featured: false
---

We are presented with the following code. 
```python
import Crypto.Util.number as cun

while True:
    p = cun.getPrime(1024)
    q = p + 2
    if cun.isPrime(q):
        break

n = p * q
e = 0x10001

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

FLAG = cun.bytes_to_long(b"buckeye{?????????????????????????????????????????????????????????????}")
c = pow(FLAG, e, n)
assert pow(c, d, n) == FLAG

print(f"n = {n}")
print(f"c = {c}")

"""
Output:
n = 20533399299284046407152274475522745923283591903629216665466681244661861027880216166964852978814704027358924774069979198482663918558879261797088553574047636844159464121768608175714873124295229878522675023466237857225661926774702979798551750309684476976554834230347142759081215035149669103794924363457550850440361924025082209825719098354441551136155027595133340008342692528728873735431246211817473149248612211855694673577982306745037500773163685214470693140137016315200758901157509673924502424670615994172505880392905070519517106559166983348001234935249845356370668287645995124995860261320985775368962065090997084944099
c = 786123694350217613420313407294137121273953981175658824882888687283151735932871244753555819887540529041840742886520261787648142436608167319514110333719357956484673762064620994173170215240263058130922197851796707601800496856305685009993213962693756446220993902080712028435244942470308340720456376316275003977039668016451819131782632341820581015325003092492069871323355309000284063294110529153447327709512977864276348652515295180247259350909773087471373364843420431252702944732151752621175150127680750965262717903714333291284769504539327086686569274889570781333862369765692348049615663405291481875379224057249719713021
"""

```

as we may have expected from reading the problem, the code is performing RSA with a pair of twin primes making up the modulus $$n$$. 

When generating primes for RSA it is important to make sure that the two primes have no known relation to eachother. If they do, it opens the door to easier methods of factoring the modulus. Seeing as the two primes here are closely related (off by two), we can look for a way to solve for $$p$$ or $$q$$. 

We start by expressing $$n$$, which we know, in terms of $$p$$.

$$n = p \cdot q = p \cdot (p + 2) = p^2 + 2p$$

$$\implies p^2 + 2p - n = 0$$

We could use the quadratic formula here and we'd be done. 


However, there is another, slightly easier, way that we could've used to attain $$p$$. By now, you likely might have guessed that 

$$\lfloor \sqrt{n} \rfloor = p$$

You can take this change to convice yourself this is true, or see the proof here.

$$p^2 < p\cdot (p+2) = n = (p+1)^2 - 1 < (p+1)^2$$

Thus, the integer square root of $$n$$ will also yield us $$p$$, which can be found just by using the python function "isqrt()", which can be found in the math module. 

Let's look at one more factorization method. You may have noticed the equality:

$$p \cdot (p+2) = (p+1)^2 - 1$$

which follows directly from your favorite middle school factoring trick. 

$$p \cdot (p+2) = (p+1 -1)(p+1+1) = (p+1)^2 - 1 = n$$

which shows us we could also recover $n$ by the following equation

$$p = \sqrt{n+1} - 1$$

This is actually a simple example of a nice [factoring trick](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method) brought to us by our friend Fermat. 

Which we can implement as 
```python
from math import isqrt
import Crypto.Util.number as cun

n = 20533399299284046407152274475522745923283591903629216665466681244661861027880216166964852978814704027358924774069979198482663918558879261797088553574047636844159464121768608175714873124295229878522675023466237857225661926774702979798551750309684476976554834230347142759081215035149669103794924363457550850440361924025082209825719098354441551136155027595133340008342692528728873735431246211817473149248612211855694673577982306745037500773163685214470693140137016315200758901157509673924502424670615994172505880392905070519517106559166983348001234935249845356370668287645995124995860261320985775368962065090997084944099
c = 786123694350217613420313407294137121273953981175658824882888687283151735932871244753555819887540529041840742886520261787648142436608167319514110333719357956484673762064620994173170215240263058130922197851796707601800496856305685009993213962693756446220993902080712028435244942470308340720456376316275003977039668016451819131782632341820581015325003092492069871323355309000284063294110529153447327709512977864276348652515295180247259350909773087471373364843420431252702944732151752621175150127680750965262717903714333291284769504539327086686569274889570781333862369765692348049615663405291481875379224057249719713021

p = isqrt(n+1) - 1

phi = (p-1) * (p+1)

d = pow(65537, -1, phi)

pt = pow(c, d, n)

print(cun.long_to_bytes(pt).decode())
```
Which gives us the flag `buckeye{B3_TH3R3_OR_B3_SQU4R3__abcdefghijklmonpqrstuvwxyz__0123456789}`
A misconception many people have that may be further brought upon by this problem is that this RSA vulnerability relies on how close the two primes are to eachother. This is false, the vulnerability primarily comes from the fact that the relation between the two primes was exposed to us. Note the following example where $p$ and $q$ are spaced by a much larger number

If we let $$q = p + 2^{32}$$, then we have 

$$n = p \cdot (p+2^{32}) =(p + 2^{31} - 2^{31})(p+2^{31}+2^{31}) = (p + 2^{31})^2 - 2^{62}$$

We can then recover $$p$$ using a similar method as our original problem.

Hopefully this example shows that Fermat's method works no matter how far apart the primes are. It is always better just not to use related primes.