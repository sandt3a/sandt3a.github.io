---
title: "Modern Cryptography Lab 1: From XOR to SHA1 Password Cracking"
published: 2026-05-12
description: "Working through Cryptopals Set 1 (first six challenges) and the MysteryTwister C3 SHA1 password cracking challenge, covering encoding conversion, XOR analysis, repeating-key cryptanalysis, and constraint-based hash cracking."
image: ""
tags:
  - Cryptography
  - Cryptopals
  - SHA1
  - XOR
category: "Lab Notes"
draft: false
lang: en
---

This modern cryptography lab consists of two parts. The first part covers the first six challenges of [Cryptopals Set 1](http://www.cryptopals.com/sets/1), focusing on encoding conversion, XOR operations, and repeating-key XOR. The second part is the MysteryTwister C3 challenge [Cracking SHA1-Hashed Passwords](https://www.mysterytwisterc3.org/en/challenges/level-2/cracking-sha1-hashed-passwords), where the goal is to recover the original password from a SHA1 hash and keyboard fingerprint information.

These two sets of problems appear different at first glance: the former leans toward implementation and frequency analysis, while the latter leans toward search-space modeling. But they share a common thread: don't blindly brute-force -- instead, model every piece of known structure as a constraint.

## Lab Environment

The lab was completed using Python 3. Encoding conversions rely primarily on the `base64` standard library, SHA1 verification uses the `hashlib` standard library, and combinatorial search uses `itertools`.

The main scripts in the directory are:

- `chal1.py` through `chal6.py`: Cryptopals Set 1, challenges 1 through 6
- `4.txt`, `6.txt`: input data provided by the respective challenges
- `mtc3-sha1.py`: MTC3 SHA1 password cracking script

## Hex to Base64

The first challenge is to convert a hex string to Base64. The key point here is that both hex and Base64 are textual representations of byte sequences. The correct approach is to first decode the hex into raw bytes, then encode those bytes in Base64.

```python
from base64 import b64encode

s = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
raw = bytes.fromhex(s)
print(b64encode(raw))
```

Output:

```text
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
```

This exercise is not an attack in itself -- it simply clarifies the boundary between "encoding" and "encryption": Base64 is not encryption, and hex is not encryption. They are just different ways of displaying bytes.

## Fixed XOR

The second challenge asks for a byte-by-byte XOR of two equal-length hex strings. Implementation involves converting both inputs to bytes, then XORing them byte by byte.

```python
def xor(a: str, b: str) -> str:
    a = bytes.fromhex(a)
    b = bytes.fromhex(b)
    assert len(a) == len(b)
    return bytes(a[i] ^ b[i] for i in range(len(a))).hex()
```

I hit one small pitfall here: the XOR result is raw bytes, and you should not call `bytes.fromhex()` on it again. Simply use `.hex()` to display the result as a hex string.

Lab output:

```text
746865206b696420646f6e277420706c6179
```

## Single-byte XOR Cipher

The third challenge provides a ciphertext encrypted with single-byte XOR and asks us to recover the plaintext. Since the key is only one byte, there are at most 256 possibilities -- simply try them all.

The real question is not whether we can enumerate, but how to judge which candidate plaintext looks more like English. The simplest approach is to score common English characters, such as the letters in `ETAOIN SHRDLU` and spaces.

```python
FREQ = "ETAOIN SHRDLU"

def score(text: bytes) -> float:
    return sum(chr(b).upper() in FREQ for b in text)

best = max(
    (bytes(b ^ key for b in ciphertext) for key in range(256)),
    key=score,
)
```

The recovered plaintext is:

```text
Cooking MC's like a pound of bacon
```

The corresponding single-byte key is `88`, which is the ASCII character `X`.

## Detect Single-character XOR

The fourth challenge extends the third to multiple lines of input: among several hundred lines of hex strings, find the one that has been encrypted with single-byte XOR.

The approach reuses the scoring function from challenge 3. For each line and each key, attempt decryption, then keep the result with the highest global score.

```python
best = None
best_score = -1

with open("4.txt") as f:
    for line in f:
        ciphertext = bytes.fromhex(line.strip())
        for key in range(256):
            candidate = bytes(b ^ key for b in ciphertext)
            current_score = score(candidate)
            if current_score > best_score:
                best_score = current_score
                best = candidate
```

The most common mistake here is forgetting to decode each line from hex into bytes. If you XOR the hex text directly, you are operating on the characters `'0'` through `'f'` rather than the actual ciphertext.

The recovered plaintext is:

```text
Now that the party is jumping
```

## Implement Repeating-key XOR

The fifth challenge implements repeating-key XOR -- using a short key to cyclically XOR an entire plaintext:

```python
def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    return bytes(
        plaintext[i] ^ key[i % len(key)]
        for i in range(len(plaintext))
    )
```

Given the key `ICE` and the challenge plaintext, the ciphertext hex output is:

```text
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
```

The core problem with repeating-key XOR is this: if the key is short enough, the ciphertext retains a periodic structure. The next challenge exploits this structure to recover the key.

## Break Repeating-key XOR

The sixth challenge provides a Base64-encoded ciphertext encrypted with a repeating-key XOR of unknown length. The cracking process can be broken into three steps.

Step one: guess the key size. This uses Hamming distance -- the number of differing bits between two byte strings. For each candidate key size, slice the ciphertext into blocks, compute the average normalized Hamming distance between adjacent blocks (dividing by key size). A smaller distance suggests the blocks are more similar, as expected when both originate from natural language under the same key period.

```python
def hamming(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))
```

Step two: transpose the ciphertext. Assuming a key size of `k`, the bytes at positions `0, k, 2k...` are all encrypted by the same key byte, as are bytes `1, k+1, 2k+1...`, and so on. This decomposes the repeating-key XOR problem into multiple single-byte XOR problems.

Step three: run single-byte XOR frequency analysis on each transposed block, assemble the full key, and decrypt the entire text.

In practice, if you only pick the minimum normalized distance, you can easily be misled into `key size = 2`. A more robust approach is to try the top several candidate lengths and re-score by plaintext quality. My candidate key sizes were:

```text
[2, 5, 3, 29, 18]
```

The final key recovered was:

```text
Terminator X: Bring the noise
```

The decrypted result is lyrics from Vanilla Ice. The takeaway from this challenge is: statistical indicators can help narrow down the options, but don't treat any single metric as an absolute conclusion. Performing a secondary verification on the top few candidates is generally more reliable than trusting only the minimum.

## MTC3: Cracking SHA1-Hashed Passwords

The second part is the MysteryTwister C3 SHA1 password cracking challenge. The target SHA1 hash is:

```text
67ae1a64661ac8b4494666f58c4822408dd0a3e4
```

The challenge also provides a keyboard fingerprint image. Based on the fingerprint positions in the image, the keys that were pressed roughly include:

- Letter keys: `Q`, `W`, `I`, `N`
- Number keys: `5`, `8`, `0`
- Symbol keys: `+ * ~`
- Modifier keys: left and right `Shift`
- Navigation keys: arrow keys, numpad `2`, `4`, `6`, `8`, `Enter`

At first glance, it is tempting to include every key with a fingerprint as a password character, which would make the search space enormous. But reasoning from the login scenario leads to further refinement: the arrow keys, numpad, and Enter are likely traces from navigating the interface after login, not part of the password; Shift is a modifier key and does not produce a character on its own.

Therefore, the actual password character keys can be narrowed down to 8:

```text
Q W 5 8 0 I + N
```

Since the keyboard layout is German QWERTZ, each key must also consider both shifted and unshifted variants. For example:

```python
pairs = [
    ["q", "Q"],
    ["w", "W"],
    ["5", "%"],
    ["8", "("],
    ["0", "="],
    ["i", "I"],
    ["+", "*"],
    ["n", "N"],
]
```

Assuming each key is pressed exactly once, the search space is:

```text
2^8 * 8! = 10,321,920
```

This is entirely tractable for direct enumeration in Python. The core verification logic:

```python
import hashlib
import itertools

target = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"

for choices in itertools.product(*pairs):
    for perm in itertools.permutations(choices, 8):
        password = "".join(perm)
        if hashlib.sha1(password.encode()).hexdigest() == target:
            print(password)
            raise SystemExit
```

The recovered password is:

```text
(Q=win*5
```

Mapping this back to the keyboard input sequence, it can be interpreted as:

- `8 + Shift` produces `(`
- `Q + Shift` produces `Q`
- `0 + Shift` produces `=`
- `w`, `i`, `n` are typed directly
- `+ + Shift` produces `*`
- `5` is typed directly

The most critical insight here is not about SHA1 itself. SHA1 is a one-way hash and cannot be directly "decrypted". The real breakthrough comes from the side-channel information provided by the challenge: the keyboard fingerprints leak the candidate character set, the Shift key leaks case and symbol variants, and the post-login navigation operations can be excluded from the password characters. After these constraint reductions, hash cracking becomes a manageable exhaustive verification.

## Summary

This lab starts from simple encoding conversions and gradually progresses to XOR cryptanalysis and SHA1 password search. A few important takeaways:

- Encoding is not encryption. Before tackling a problem, clearly distinguish hex, Base64, and raw bytes.
- The security of XOR depends entirely on how the key is used. Single-byte XOR can be brute-forced directly; repeating-key XOR exposes a periodic structure.
- English frequency analysis, though simple, is highly effective for both single-byte XOR and repeating-key XOR.
- Hamming distance can estimate repeating-key length, but multiple candidates should be verified with a secondary check.
- Hashes cannot be reversed, but they can be verified against a sufficiently small candidate space.
- What truly reduces complexity is often not computational power, but how well you model the constraints given by the problem.

From this perspective, the modern cryptography lab is not just about implementing a particular algorithm. More importantly, it is about understanding how data representation, key structure, statistical features, and external information collectively affect the security of a system.
