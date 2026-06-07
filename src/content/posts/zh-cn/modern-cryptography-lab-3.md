---
title: "现代密码学实验三：RSA 公钥密码实现与未遮掩消息分析"
published: 2026-05-26
description: "整理 Cryptopals Set 5 Challenge 39 与 Project Euler 182 实验，记录 RSA 密钥生成（Miller-Rabin 素性检验）、加密解密实现、扩展欧几里得算法求模逆，以及未遮掩消息的数学分析与最小化搜索。"
image: ""
tags:
  - 密码学
  - Cryptopals
  - RSA
  - Project Euler
  - 数论
  - Miller-Rabin
category: "实验记录"
draft: false
lang: "zh_CN"
---

这次现代密码学实验围绕 RSA 公钥密码体制展开，由两个题目组成：第一个是 [Cryptopals Set 5 Challenge 39](http://www.cryptopals.com/sets/5/challenges/39)，要求从零实现 RSA 的密钥生成、加密和解密；第二个是 [Project Euler Problem 182](https://projecteuler.net/problem=182)，要求在给定素数 p 和 q 的前提下，找到所有能使"未遮掩消息"（unconcealed messages）数量最小的公钥指数 e，并求和。

两个题目关注的方向不同：Challenge 39 偏工程实现，重点是 Miller-Rabin 素性检验和模逆计算；Problem 182 则更偏数学分析，需要从 RSA 不变元的性质出发理解为什么某些公钥指数 e 会让更多消息满足 $m^e \equiv m \pmod{n}$。但两者的共同基础是 RSA 的数学框架。

## 实验环境

实验使用 Python 3 完成，不依赖外部密码库。大整数模幂运算使用 Python 内置的 `pow()` 函数（三参数形式），随机数使用标准库 `random`，最大公约数使用 `math.gcd`。

目录中的主要脚本如下：

- `chal39.py`：Cryptopals Challenge 39 — 实现 RSA
- `pe182.py`：Project Euler Problem 182 — RSA 未遮掩消息最小化

## 数学基础

两个题目共享以下数论基础。

### 欧拉函数与欧拉定理

对于正整数 n，欧拉函数 φ(n) 表示小于 n 且与 n 互素的正整数个数。当 n = pq（p、q 为不同素数）时，φ(n) = (p-1)(q-1)。

欧拉定理指出：若 gcd(a, n) = 1，则 $a^{\varphi(n)} \equiv 1 \pmod{n}$。RSA 解密正确性的核心保证来源于此：由于 $ed \equiv 1 \pmod{\varphi(n)}$，存在整数 k 使得 $ed = 1 + k\varphi(n)$，于是

$$m^{ed} \equiv m^{1 + k\varphi(n)} \equiv m \cdot (m^{\varphi(n)})^k \equiv m \pmod{n}$$

### 扩展欧几里得算法

RSA 的私钥 d 是公钥 e 在模 φ(n) 下的乘法逆元，即满足 $ed \equiv 1 \pmod{\varphi(n)}$。求模逆需要扩展欧几里得算法（Extended GCD），它不仅计算两个整数的最大公约数，还找到满足 $ax + by = \gcd(a, b)$ 的整数系数 x 和 y。

```python
def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def mod_inverse(a: int, m: int) -> int:
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"modular inverse does not exist: gcd({a}, {m}) = {g}")
    return x % m
```

扩展欧几里得算法的递归实现优雅但容易出错。关键在于理解递归返回时的系数如何变换：如果已知 `b * x1 + (a % b) * y1 = g`，代入 `a % b = a - (a // b) * b`，重组后得到 `a * y1 + b * (x1 - (a // b) * y1) = g`，因此新的系数为 `(y1, x1 - (a // b) * y1)`。

## Challenge 39：Implement RSA

Challenge 39 的任务是实现教科书级别的 RSA，包含三个关键部分：密钥生成、加密和解密。

### 密钥生成

RSA 密钥生成需要两个大素数 p 和 q。在真实应用中，p 和 q 通常为 1024 位或 2048 位，但挑战中使用较小的位数（64 位）以便于调试。

生成素数使用了 Miller-Rabin 概率素性检验：

```python
def is_prime(n: int, k: int = 40) -> bool:
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True
```

Miller-Rabin 算法的核心思想是把 n - 1 写成 $2^r \cdot d$（d 为奇数），然后检查 $a^d, a^{2d}, a^{4d}, \ldots, a^{2^r d}$ 这个序列。如果 n 是素数，这个序列要么全部是 1，要么在某处出现 -1。如果两个条件都不满足，n 一定是合数。进行 k 轮测试后，错误概率最多为 $1/4^k$，这里 k=40 已经足够安全。

有了素性检验后，随机生成指定位数的奇数并测试，直到找到素数：

```python
def generate_prime(bits: int = 64) -> int:
    while True:
        candidate = random.getrandbits(bits)
        candidate |= 1  # 确保奇数
        if is_prime(candidate):
            return candidate
```

完整的密钥生成函数如下：

```python
def generate_rsa_keys(bits: int = 64) -> tuple[tuple[int, int], tuple[int, int]]:
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 3
    while gcd(e, phi) != 1:
        e += 2

    d = mod_inverse(e, phi)
    return (e, n), (d, n)
```

这里选择 e = 3 作为公钥指数是一个有争议的做法——虽然 e = 3 在特定条件下（小消息、广播攻击）存在安全隐患，但对于教科书 RSA 实现来说非常简洁。实际应用中更常用 e = 65537（即 $2^{16}+1$），它是一个费马素数，既保证计算效率又避免了小 e 带来的问题。

### 加密与解密

加密和解密的核心就是模幂运算。Python 内置的 `pow(base, exp, mod)` 使用了快速幂取模算法，时间复杂度为 $O(\log \text{exp})$：

```python
def rsa_encrypt(plaintext: int, pubkey: tuple[int, int]) -> int:
    e, n = pubkey
    return pow(plaintext, e, n)

def rsa_decrypt(ciphertext: int, privkey: tuple[int, int]) -> int:
    d, n = privkey
    return pow(ciphertext, d, n)
```

测试用一个简单的数字消息验证加解密正确性：

```text
Original:  42
Encrypted: 8241602486128260 (示例，每次运行 n 不同)
Decrypted: 42
Match: True
```

对于文本消息，可以使用 `int.from_bytes` 将字节串转换为整数：

```python
text = b"Hello, RSA!"
m = int.from_bytes(text, "big")
# ... 加密解密后 ...
recovered = dec.to_bytes((dec.bit_length() + 7) // 8, "big")
```

这里需要注意：消息转换为整数后必须小于 n，否则无法正确解密。因此需要根据消息大小选择合适的密钥长度。

### 实现中的关键细节

RSA 实现中有几个容易出错的地方：

- **p 和 q 必须不同**。如果 p = q，则 φ(n) = p(p-1) 而非 (p-1)(q-1)，解密会失效。
- **e 必须与 φ(n) 互素**，否则模逆不存在。这里如果 e=3 不满足条件就 +2 推进（跳到下一个奇数），直到 gcd(e, phi) = 1。
- **Miller-Rabin 中要处理 n=2 和 n=3 的边界情况**，以及排除偶数。
- **模逆计算后需要取模**：扩展欧几里得算法返回的 x 可能是负数，需要用 `x % m` 得到正的模逆值。

## Project Euler 182：RSA Encryption — Minimizing Unconcealed Messages

Project Euler 的 182 题在数学上比 Challenge 39 深入得多。给定 p = 1009，q = 3643，n = pq，φ(n) = (p-1)(q-1) = 1008 × 3642 = 3671136，要求在 1 < e < φ(n) 且 gcd(e, φ(n)) = 1 范围内，找到使"未遮掩消息"数量最小的所有 e，并求和。

### 未遮掩消息的数学定义

在 RSA 中，"未遮掩消息"（unconcealed message）是指那些加密后等于自身的消息，即满足：

$$m^e \equiv m \pmod{n}$$

对任何 RSA 系统，总是存在一些平凡的未遮掩消息（m = 0 一定满足，m = 1 也满足）。但当 e 选择不当时，可能会有更多的 m 满足这个条件，这就削弱了加密的隐蔽性。

一个问题自然地浮现：给定了 n = pq，有多少个 m 满足这个条件？

### 利用中国剩余定理分解

由于 n = pq 且 p、q 互素，中国剩余定理（CRT）告诉我们：$m^e \equiv m \pmod{n}$ 等价于下面两个同余式同时成立：

$$m^e \equiv m \pmod{p}$$
$$m^e \equiv m \pmod{q}$$

在模素数 p 下，$m^e \equiv m$ 等价于 $m(m^{e-1} - 1) \equiv 0$，即要么 $m \equiv 0 \pmod{p}$，要么 $m^{e-1} \equiv 1 \pmod{p}$。

由费马小定理，$m^{p-1} \equiv 1 \pmod{p}$（对 m 不被 p 整除的情况）。方程 $m^{e-1} \equiv 1 \pmod{p}$ 在模 p 的乘法群（阶为 p-1）中解的数量等于 $\gcd(e-1, p-1)$。加上 m = 0，模 p 下的解共有 $1 + \gcd(e-1, p-1)$ 个。

同理模 q 下有 $1 + \gcd(e-1, q-1)$ 个解。根据中国剩余定理的乘法原理，模 n 下的解的总数为两者的乘积：

$$U(e) = (1 + \gcd(e-1, p-1)) \times (1 + \gcd(e-1, q-1))$$

这就是 Project Euler 182 的核心公式。

### 求解过程

有了公式，问题变成了一个搜索优化问题。p-1 = 1008，q-1 = 3642，φ = 3671136。

第一步：遍历所有有效的 e（1 < e < φ，gcd(e, φ) = 1），计算 U(e)，找出最小值。

第二步：遍历所有有效的 e，找出达到该最小值的那些，求和。

```python
from math import gcd

p = 1009
q = 3643
phi = (p - 1) * (q - 1)
p1 = p - 1  # 1008
q1 = q - 1  # 3642

def unconcealed_count(e: int) -> int:
    return (1 + gcd(e - 1, p1)) * (1 + gcd(e - 1, q1))

# 第一步：找最小值
min_count = float("inf")
for e in range(2, phi):
    if gcd(e, phi) == 1:
        u = unconcealed_count(e)
        if u < min_count:
            min_count = u

# 第二步：求和
total = 0
for e in range(2, phi):
    if gcd(e, phi) == 1 and unconcealed_count(e) == min_count:
        total += e
```

这个算法的核心洞察在于：U(e) 的值完全由 $\gcd(e-1, p-1)$ 和 $\gcd(e-1, q-1)$ 决定。要使 U(e) 最小，需要让这两个 gcd 尽可能小——但 e-1 是偶数（因为 e 必须是奇数才能与 φ 互素），所以与 1008（有很多 2 因子）的 gcd 至少为 2。

每个 e 的 U(e) 值只需计算一次，且 φ 范围约为 3.67 × 10⁶，直接遍历完全可行。

### 为什么未遮掩消息是一个安全问题

如果存在大量的 m 使得 $m^e \equiv m \pmod{n}$，这意味着：
- 攻击者如果碰巧选择了这样一个 m，加密并没有改变它——密文就是明文本身
- 在极端情况下（U(e) 很大），有相当比例的消息在 RSA 加密下是"透明的"
- 这不是 RSA 算法的 bug，而是公钥指数 e 选择不当导致的后果

事实上，如果 e = 1（虽然通常在要求范围之外），则 U(1) = (1 + gcd(0, p-1)) × (1 + gcd(0, q-1)) = (1 + p-1) × (1 + q-1) = pq = n，即所有消息都是未遮掩的——因为"加密"退化为恒等变换。

这就是为什么实际应用中通常选择 e = 65537（$2^{16}+1$）：它是一个素数，gcd(e-1, p-1) = gcd(65536, p-1) 只有 p-1 与 65536 共享的少数 2 因子，通常非常小，从而保持 U(e) 接近最小值。

## 小结

这次实验从工程实现和数学分析两个角度考察了 RSA 公钥密码体制。几个重要的体会是：

- **RSA 的安全性根植于大整数分解的困难性，但工程实现中更需要注意的是边界条件**。p 和 q 必须不同，e 必须与 φ(n) 互素，消息必须小于 n。这些看似简单的约束在教科书实现中容易遗漏，但任何一条不满足都会导致解密失败。
- **Miller-Rabin 是概率算法，但可以通过增加测试轮数将错误概率降到任意低**。40 轮测试已经足以满足实际应用。理解它的原理——利用 $a^{2^r d} \bmod n$ 的序列行为——比背参数更有价值。
- **模幂运算是 RSA 的性能核心**。Python 内置的 `pow(a, b, n)` 使用了快速模幂算法（平方-乘算法），时间复杂度为 $O(\log b)$，比直接计算 $a^b$ 再取模高效得多。对于 2048 位的 RSA，这个优化使得加密/解密在毫秒级别完成。
- **未遮掩消息问题揭示了 RSA 的一个微妙之处**：公钥指数 e 的选择不仅影响加密效率，还直接影响有多少消息在加密下"保持原样"。公式 $U(e) = (1 + \gcd(e-1, p-1))(1 + \gcd(e-1, q-1))$ 以简洁的形式展示了 e 的选择如何通过数论性质影响安全性。
- **数论工具是密码学的基础语言**：欧拉定理保证了 RSA 解密正确性，扩展欧几里得算法用于求模逆，中国剩余定理用于分解同余方程，费马小定理用于推导 U(e) 公式。这些工具在整个密码学中反复出现，掌握它们的推导比单纯记住结论更重要。

从这两个题目看，现代密码学实验三不只是在写 RSA 的代码——更重要的是理解 RSA 数学结构中"哪些参数是自由的、哪些参数是约束的"，以及参数选择如何从数论层面影响安全性。
