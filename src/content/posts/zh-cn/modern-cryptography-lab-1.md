---
title: "现代密码学实验一：从 XOR 到 SHA1 口令破解"
published: 2026-05-12
description: "整理 Cryptopals Set 1 前六题与 MysteryTwister C3 SHA1 口令破解实验，记录编码转换、异或分析、重复密钥破解和基于约束缩减的哈希破解思路。"
image: ""
tags:
  - 密码学
  - Cryptopals
  - SHA1
  - XOR
category: "实验记录"
draft: false
lang: "zh_CN"
---

这次现代密码学实验主要由两部分组成：第一部分是 [Cryptopals Set 1](http://www.cryptopals.com/sets/1) 的前六个练习，围绕编码转换、异或运算和重复密钥 XOR 展开；第二部分是 MysteryTwister C3 的 [Cracking SHA1-Hashed Passwords](https://www.mysterytwisterc3.org/en/challenges/level-2/cracking-sha1-hashed-passwords)，目标是从一个 SHA1 哈希和键盘指纹信息中恢复原始口令。

这两组题看起来方向不同：前者偏向实现和频率分析，后者偏向搜索空间建模。但它们背后的共同点是一样的：不要盲目暴力枚举，而是尽可能把已知结构转化成约束。

## 实验环境

实验使用 Python 3 完成。编码转换主要依赖标准库 `base64`，SHA1 验证使用标准库 `hashlib`，排列组合搜索使用 `itertools`。

目录中的主要脚本如下：

- `chal1.py` 到 `chal6.py`：Cryptopals Set 1 前六题
- `4.txt`、`6.txt`：对应挑战给出的输入数据
- `mtc3-sha1.py`：MTC3 SHA1 口令破解脚本

## Hex to Base64

第一题是把十六进制字符串转换成 Base64。这里需要注意，hex 和 Base64 都是字节序列的文本表示形式，转换时应先把 hex 解码成原始 bytes，再对 bytes 做 Base64 编码。

```python
from base64 import b64encode

s = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
raw = bytes.fromhex(s)
print(b64encode(raw))
```

输出结果为：

```text
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
```

这个练习本身不涉及攻击，只是确认后续题目中“编码”和“加密”的边界：Base64 不是加密，hex 也不是加密，它们只是不同的字节展示方式。

## Fixed XOR

第二题要求对两个等长的 hex 字符串逐字节 XOR。实现时先把两个输入都转成 bytes，然后逐字节计算异或。

```python
def xor(a: str, b: str) -> str:
    a = bytes.fromhex(a)
    b = bytes.fromhex(b)
    assert len(a) == len(b)
    return bytes(a[i] ^ b[i] for i in range(len(a))).hex()
```

这题里我踩过一个小坑：XOR 得到的是原始 bytes，不应该再对结果调用 `bytes.fromhex()`。最后只需要用 `.hex()` 把结果展示成十六进制即可。

实验输出：

```text
746865206b696420646f6e277420706c6179
```

## Single-byte XOR Cipher

第三题给出一段被单字节 XOR 加密的密文，需要恢复明文。因为密钥只有一个字节，所以最多只有 256 种可能，直接全部尝试即可。

关键不在于能不能枚举，而在于如何判断哪个候选明文更像英语文本。最简单的办法是给常见英文字符加分，例如 `ETAOIN SHRDLU` 中的字母和空格。

```python
FREQ = "ETAOIN SHRDLU"

def score(text: bytes) -> float:
    return sum(chr(b).upper() in FREQ for b in text)

best = max(
    (bytes(b ^ key for b in ciphertext) for key in range(256)),
    key=score,
)
```

最终恢复出的明文为：

```text
Cooking MC's like a pound of bacon
```

对应的单字节 key 是 `88`，也就是 ASCII 字符 `X`。

## Detect Single-character XOR

第四题把第三题扩展到多行输入：在几百行 hex 字符串中，找出哪一行被单字节 XOR 加密过。

做法是复用第三题的评分函数，对每一行、每一个 key 都尝试解密，然后保留全局最高分的结果。

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

这里最容易犯的错误是忘记把每一行从 hex 解码成 bytes。如果直接拿 hex 文本参与 XOR，实际上处理的是字符 `'0'` 到 `'f'`，而不是密文本身。

恢复出的明文为：

```text
Now that the party is jumping
```

## Implement Repeating-key XOR

第五题实现重复密钥 XOR，也就是用一个短 key 循环异或整段明文：

```python
def repeating_key_xor(plaintext: bytes, key: bytes) -> bytes:
    return bytes(
        plaintext[i] ^ key[i % len(key)]
        for i in range(len(plaintext))
    )
```

给定 key 为 `ICE`，对题目中的明文加密后，输出密文 hex：

```text
0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
```

重复密钥 XOR 的核心问题是：如果 key 足够短，密文会保留周期性结构。下一题就是利用这种结构反向恢复密钥。

## Break Repeating-key XOR

第六题给出一段 Base64 编码的密文，它由未知长度的重复密钥 XOR 加密而来。破解过程可以拆成三步。

第一步是猜测 key size。这里使用 Hamming distance，也就是两个字节串之间不同 bit 的数量。对候选 key size 切块，计算相邻块的平均汉明距离，再除以 key size 做归一化。距离越小，说明两个块越像自然语言经过同一类密钥周期加密后的结果。

```python
def hamming(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))
```

第二步是转置密文。假设 key size 是 `k`，那么第 `0, k, 2k...` 个密文字节都由同一个 key 字节加密，第 `1, k+1, 2k+1...` 个密文字节也由同一个 key 字节加密。这样就可以把重复密钥 XOR 拆成多个单字节 XOR 问题。

第三步是对每一组转置后的密文运行单字节 XOR 频率分析，拼出完整 key，再解密全文。

实验中如果只取最小归一化距离，容易误选到 `key size = 2`。更稳妥的做法是取前几个候选长度都试一遍，然后按明文质量重新评分。我的候选 key size 为：

```text
[2, 5, 3, 29, 18]
```

最终选出的 key 是：

```text
Terminator X: Bring the noise
```

解密结果是 Vanilla Ice 的歌词。这个题的收获是：统计指标可以帮助缩小范围，但不要把单一指标当成绝对结论。对前几个候选做二次验证，通常比只相信最小值更可靠。

## MTC3：Cracking SHA1-Hashed Passwords

第二部分是 MysteryTwister C3 的 SHA1 口令破解题。题目给出的目标 SHA1 哈希为：

```text
67ae1a64661ac8b4494666f58c4822408dd0a3e4
```

题目还给出了一张键盘指纹图。根据图中的指纹位置，可以确定被按过的键大致包括：

- 字母键：`Q`、`W`、`I`、`N`
- 数字键：`5`、`8`、`0`
- 符号键：`+ * ~`
- 修饰键：左右 `Shift`
- 导航键：方向键、小键盘 `2`、`4`、`6`、`8`、`Enter`

一开始很容易把所有出现指纹的键都当成密码字符，这样搜索空间会很大。但结合登录场景可以做进一步判断：方向键、小键盘和 Enter 很可能是登录后操作界面留下的痕迹，不一定属于密码；Shift 是修饰键，本身也不产生字符。

因此真正需要考虑的密码字符键可以缩小到 8 个：

```text
Q W 5 8 0 I + N
```

由于键盘布局是 German QWERTZ，每个键还需要考虑 shifted 和 unshifted 两种字符。例如：

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

如果假设每个键恰好按一次，那么搜索空间就是：

```text
2^8 * 8! = 10,321,920
```

这个规模用 Python 直接枚举完全可以接受。核心验证逻辑如下：

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

最终恢复出的密码是：

```text
(Q=win*5
```

把它映射回键盘输入过程，可以解释为：

- `8 + Shift` 输入 `(`
- `Q + Shift` 输入 `Q`
- `0 + Shift` 输入 `=`
- `w`、`i`、`n` 直接输入
- `+ + Shift` 输入 `*`
- `5` 直接输入

这个题最关键的不是 SHA1 本身。SHA1 是单向哈希，不能直接“解密”。真正的突破口是题目额外给出的侧信道信息：键盘指纹泄露了候选字符集合，Shift 泄露了大小写和符号变体，登录后的导航操作又可以从密码字符中剔除。经过这些约束缩减后，哈希破解就变成了可控规模的穷举验证。

## 小结

这次实验从简单编码转换开始，逐步过渡到 XOR 密码分析和 SHA1 口令搜索。几个比较重要的体会是：

- 编码不是加密，处理题目前要先分清 hex、Base64 和原始 bytes。
- XOR 的安全性完全取决于密钥使用方式。单字节 XOR 可以直接枚举，重复密钥 XOR 会暴露周期结构。
- 英文频率分析虽然简单，但在单字节 XOR 和重复密钥 XOR 中非常有效。
- Hamming distance 能用于估计重复密钥长度，但需要对多个候选做二次验证。
- 哈希不能被反向解密，但可以在足够小的候选空间内做验证式搜索。
- 真正降低复杂度的往往不是算力，而是对题目条件的建模。

从这个角度看，现代密码学实验不只是写出某个算法，更重要的是理解数据表示、密钥结构、统计特征和外部信息如何共同影响一个系统的安全性。
