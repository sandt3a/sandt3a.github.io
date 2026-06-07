---
title: "现代密码学实验二：AES 分组密码模式分析与 ECB/CBC 攻击"
published: 2026-05-19
description: "整理 Cryptopals Set 2 全部八题与 MysteryTwister C3 BAC ePassport 实验，记录 PKCS#7 填充、AES-CBC 实现、ECB 逐字节解密、CBC 比特翻转攻击以及基于 MRZ 的密钥派生与解密思路。"
image: ""
tags:
  - 密码学
  - Cryptopals
  - AES
  - ECB
  - CBC
  - BAC
category: "实验记录"
draft: false
lang: "zh_CN"
---

这次现代密码学实验主要由两部分组成：第一部分是 [Cryptopals Set 2](http://www.cryptopals.com/sets/2) 的八道题，围绕 AES 分组密码的 ECB 和 CBC 两种工作模式展开，涵盖填充、模式检测、逐字节解密、剪切粘贴攻击和比特翻转攻击；第二部分是 MysteryTwister C3 的 [AES Key — Encoded in the Machine Readable Zone of a European ePassport](https://www.mysterytwisterc3.org/en/challenges/level-2/aes-key--encoded-in-the-machine-readable-zone-of-a-european-epassport)，目标是从电子护照 MRZ 的校验位恢复出发，派生 BAC 加密密钥并解密密文。

这两组题核心围绕同一件事：ECB 和 CBC 的设计差异如何被利用。ECB 的确定性导致重复块泄露结构信息，CBC 虽然掩盖了重复块，但其链式依赖关系让攻击者可以通过翻转前一密文块来控制下一块的明文内容。MTC3 的 BAC 题目则是从侧信道信息（护照 MRZ）入手，展示密钥空间如何从"不可能穷举"缩减到"足够小即可恢复"。

## 实验环境

实验使用 Python 3 完成。AES 加密使用 `pycryptodome` 库的 `Crypto.Cipher.AES`，哈希使用标准库 `hashlib`，Base64 使用标准库 `base64`。

目录中的主要脚本如下：

- `chal9.py` 到 `chal16.py`：Cryptopals Set 2 全部八题
- `mtc3-bac.py`：MTC3 BAC ePassport 破解脚本
- `lab2_solutions.py`：统一整合版本，包含所有题目的求解函数
- `test_lab2_solutions.py`：单元测试
- `data/cryptopals_10.txt`：Challenge 10 的 Base64 密文数据

## 公共工具函数

整个实验中多个题目复用了以下工具函数：

```python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def split_blocks(data: bytes, block_size: int = 16) -> list[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length

def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    padding_length = data[-1]
    if padding_length == 0 or padding_length > block_size:
        raise ValueError("invalid PKCS#7 padding length")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("invalid PKCS#7 padding bytes")
    return data[:-padding_length]
```

这些函数看似简单，但它们构成了后续所有攻击的基础构件——XOR 是 CBC 链式操作的核心，PKCS#7 是分组密码补齐的工业标准，切块则是 ECB 分析的第一步。

## PKCS#7 Padding

第九题单独实现 PKCS#7 填充。如果分组大小为 N、明文长度为 M，则填充 `N - M % N` 个字节，每个字节的值都是填充长度本身。

```python
def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length
```

以 `"YELLOW SUBMARINE"`（16 字节）为例，当 `block_size = 20` 时，填充结果末尾附加 4 个 `\x04`：

```text
b'YELLOW SUBMARINE\x04\x04\x04\x04'
```

PKCS#7 的价值不仅在于补齐分块，它同时是去填充时判断数据完整性的依据：如果最后 K 个字节不是 K 个值为 K 的字节，说明数据被篡改或解密密钥错误。这一特性后来在 padding oracle 攻击中会被利用。

## Implement CBC Mode

第十题要求从零实现 AES-128 CBC 模式的解密。CBC 解密的核心是：每个密文块先 ECB 解密，再与前一密文块（或 IV，对第一个块）异或：

```python
def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    previous = iv
    plaintext = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted = aes_ecb_decrypt(block, key)
        plaintext.extend(xor_bytes(decrypted, previous))
        previous = block
    return bytes(plaintext)
```

题目给出的密文是 Base64 编码的，key 为 `"YELLOW SUBMARINE"`，IV 为全零。解密并去除 PKCS#7 填充后，得到一段歌词，开头是：

```text
I'm back and I'm ringin' the bell
```

实现时需要注意两点：一是先 ECB 解密再 XOR，而不是先 XOR 再解密（那是加密的过程）；二是 CBC 模式下每个块的解密依赖于前一个密文块，但这个依赖链在解密方向上是"无状态的"——任意一个密文块都可以独立 ECB 解密，只需要前一个块的密文即可恢复明文。

## An ECB/CBC Detection Oracle

第十一题要求实现一个加密神谕（oracle），它随机选择 ECB 或 CBC 模式对输入加密（并在明文中附加随机前后缀），然后写一个检测器判断用的是哪种模式。

检测方法非常简单：ECB 模式下相同的明文块会产生相同的密文块，CBC 模式下由于 IV 的链式效应不会。只需要输入足够多的重复数据（例如 64 个 `"A"`），然后检查密文中是否存在重复的 16 字节块：

```python
def has_repeated_block(data: bytes, block_size: int = 16) -> bool:
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    return len(blocks) != len(set(blocks))
```

100 次测试中检测准确率为 100%。这个题说明了 ECB 最根本的弱点：它不是随机化的加密方案，相同的输入在相同的 key 下始终产生相同的输出。这正是后续 ECB 逐字节解密攻击的立足点。

## Byte-at-a-time ECB Decryption (Simple)

第十二题是 Set 2 的核心攻击。题目给出一个 ECB 加密神谕 `oracle(plaintext) = AES_ECB(pad(plaintext || secret))`，也就是我们的输入后面会被拼接一段未知的 secret 后缀然后加密。目标是恢复这段 secret。

攻击分为四步。

第一步是检测分块大小。逐步增加输入长度，当密文长度发生跳跃时，跳跃的差值就是 block_size：

```python
def detect_block_size() -> int:
    baseline = len(oracle(b""))
    for size in range(1, 256):
        if len(oracle(b"A" * size)) > baseline:
            return len(oracle(b"A" * size)) - baseline
    raise ValueError("failed to detect block size")
```

第二步是确认 ECB 模式。送入足够多的重复字符，检查是否有重复密文块。

第三步是确定 secret 长度。基线长度为 `len(oracle(b""))`，然后逐步增加填充字节，观察密文增长点。

第四步是逐字节恢复 secret。这是攻击的核心逻辑：精心构造一个前缀，使目标字节恰好落在一个已知块的最后一个位置。例如 block_size 为 16 时，如果已经恢复了 n 个字节，就输入 `15 - (n % 16)` 个 `"A"` 作为前缀，此时 secret 的下一个未知字节正好位于某个块的末尾。

然后暴力枚举该字节的所有 256 种可能，调用 oracle 生成候选密文，比较目标块是否匹配：

```python
recovered = bytearray()
while True:
    short = bs - 1 - (len(recovered) % bs)
    prefix = b"A" * short
    target = oracle(prefix)
    block_idx = len(recovered) // bs
    target_block = target[block_idx * bs : (block_idx + 1) * bs]

    found = False
    for guess in range(256):
        candidate = oracle(prefix + recovered + bytes([guess]))
        if candidate[block_idx * bs : (block_idx + 1) * bs] == target_block:
            recovered.append(guess)
            found = True
            break
    if not found:
        break
```

恢复出的 secret 是一段 Base64 解码后的文本：

```text
Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
```

这道题最直接的收获是：ECB 模式下，攻击者不需要知道密钥，只需要能够控制部分输入并观察输出，就能以字节为粒度逐位恢复未知数据。攻击复杂度是 `O(256 × secret_length)`，完全可行。

## ECB Cut-and-Paste

第十三题展示了 ECB 的另一个实际漏洞：由于 ECB 的每个块独立加密，攻击者可以重新排列密文块来构造合法的密文。目标是将 `role=user` 替换为 `role=admin`。

题目提供了一个 `profile_for(email)` 函数，它能生成一个类似 URL 编码的 profile 字符串并 ECB 加密。`&` 和 `=` 会被过滤，所以不能直接在 email 字段注入 `&role=admin`。

攻击策略是"剪切粘贴"：首先构造一个包含 `"admin"` 加有效 PKCS#7 填充的密文块，然后把这个块粘贴到正常 profile 的对应位置。

第一步：用 email `"A" * 10 + pkcs7_pad(b"admin")` 生成一条密文。此时 profile 结构为：

```text
email=AAAAAAAAAAadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b&uid=10&role=user
```

对应的密文分块为：
- Block 0: `email=AAAAAAAAAA`
- Block 1: `admin + 11 个 \x0b 填充`
- Block 2: `&uid=10&role=use`
- Block 3: `r + 填充`

第二步：用 email `"A" * 13` 生成另一条密文（13 个 A 可以精确对齐使 `user` 单独成块），然后将其最后一个密文块替换为 Block 1（`admin` 块）。

解密后的 profile 中，`role` 字段变成了 `admin`。

```text
Forged profile: {'email': 'AAAAAAAAAAAAA', 'uid': '10', 'role': 'admin'}
```

这个攻击的前提是：ECB 的每个分块独立加密、互不影响。替换一个密文块只会影响对应位置的明文块，前后块完全不受影响。而 CBC 模式下这种攻击不成立，因为替换一个密文块会破坏后续块的解密。

## Byte-at-a-time ECB Decryption (Harder)

第十四题在第十二题的基础上增加了一个障碍：oracle 在攻击者输入之前附加了一段随机长度的前缀。

```python
RANDOM_PREFIX = os.urandom(random.randint(8, 48))

def oracle(plaintext: bytes) -> bytes:
    return aes_ecb_encrypt(
        pkcs7_pad(RANDOM_PREFIX + plaintext + SECRET_SUFFIX), KEY
    )
```

这个随机前缀破坏了攻击者对块边界的控制。但核心思路不变：先找到办法对齐，再用逐字节攻击。

对齐方法：发送三个连续的相同块作为标记（例如 `"B" * 48`），然后尝试不同程度的 offset padding（`"A" * pad_length`）。当找到某个 pad_length 使得三个标记块恰好完整对齐到一个块的起始位置时，密文中将出现三个连续的相同密文块：

```python
def find_prefix_alignment() -> tuple[int, int]:
    marker = b"B" * BLOCK_SIZE * 3
    for pad_length in range(BLOCK_SIZE):
        ct = oracle(b"A" * pad_length + marker)
        blocks = [ct[i:i + BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        for idx in range(len(blocks) - 2):
            if blocks[idx] == blocks[idx + 1] == blocks[idx + 2]:
                return pad_length, idx
    raise ValueError("failed to align random prefix")
```

找到对齐参数后，后续的逐字节恢复过程与第十二题几乎一致。关键区别在于每个 oracle 调用都需要额外拼接 `pad_length` 个 `"A"` 作为前缀缓冲，而 secret 的起始块索引也不再是 0，而是 `ctrl_block`。

这个题目说明：即使随机前缀增加了复杂度，ECB 的确定性本质依然让攻击可行。攻击者只需要比"简单版本"多花约 `block_size` 次 oracle 调用来找到对齐点，总体复杂度几乎没有增加。

## PKCS#7 Padding Validation

第十五题将第九题中实现的填充函数反转，要求写一个严格验证并去除 PKCS#7 填充的函数。

验证规则：数据长度必须是非零的分块大小倍数；最后一个字节的值必须在 `[1, block_size]` 范围内；最后 `padding_length` 个字节必须全部等于 `padding_length`。

```python
def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("data length must be a non-zero multiple of block size")
    padding_length = data[-1]
    if padding_length == 0 or padding_length > block_size:
        raise ValueError(f"invalid PKCS#7 padding length: {padding_length}")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("invalid PKCS#7 padding bytes")
    return data[:-padding_length]
```

测试结果：

```text
Valid:   b'ICE ICE BABY\x04\x04\x04\x04' → b'ICE ICE BABY'
Invalid: b'ICE ICE BABY\x05\x05\x05\x05' → ValueError: invalid PKCS#7 padding bytes
Invalid: b'ICE ICE BABY\x01\x02\x03\x04' → ValueError: invalid PKCS#7 padding bytes
```

严格验证填充是必要的。在真实系统中，如果去填充时不检查填充字节的一致性，攻击者就可以利用 padding oracle 逐字节恢复密文——这也是 Cryptopals 后续 set 中会遇到的攻击。

## CBC Bit Flipping Attack

第十六题展示了 CBC 模式下的一个经典攻击：比特翻转。给定一个 CBC 加密神谕，它在用户输入中过滤 `;` 和 `=`（分别替换为 `%3B` 和 `%3D`），然后拼接到 `comment1=cooking%20MCs;userdata=` 和 `;comment2=...` 之间加密。目标是让最终解密后的明文包含 `;admin=true;`。

攻击利用了 CBC 解密的一个关键性质：

```text
plaintext[block N] = AES_ECB_Decrypt(ciphertext[block N]) XOR ciphertext[block N-1]
```

翻转密文块 `N-1` 的某个比特，会翻转对应位置的明文块 `N` 中的比特。因此，如果我们知道明文块 `N` 的原始值，就可以计算需要翻转哪些比特来得到想要的明文。

攻击过程：PREFIX 正好 32 字节（2 个块），用户输入从 block 2 开始。用 `"A" * 16` 作为输入，加密后再翻转 block 1（前缀的第二块）的对应比特：

```python
target = b";admin=true;"
payload = b"A" * BLOCK_SIZE
ct = bytearray(encrypt_userdata(payload))
for i, desired in enumerate(target):
    ct[BLOCK_SIZE + i] ^= ord("A") ^ desired
```

翻转后，block 2 解密出的明文从 `"AAAAAAAAAAAAAAAA"` 变成了 `";admin=true;"`，而 `is_admin` 检查通过。没有被过滤，因为 `;` 和 `=` 并没有出现在用户输入中——它们是密文块被翻转后产生的。

这个攻击的本质是：CBC 的完整性保护不足。CBC 只通过 IV 链式来打乱明文-密文映射，但没有提供认证机制。攻击者虽然不知道密钥，但可以通过操纵密文来精确控制解密后的明文比特。这也是为什么真实协议（如 TLS）后来引入了 AEAD（带认证的加密模式）如 GCM。

## MTC3：AES Key — European ePassport BAC

第二部分是 MysteryTwister C3 的 BAC ePassport 题目。题目给出了一张欧洲电子护照 MRZ（机器可读区）第二行的部分信息，其中一个校验位被隐去：

```text
12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4
```

需要：恢复缺失的校验位 → 提取 MRZ 信息 → 派生 BAC 加密密钥 `K_ENC` → 解密密文获得 codeword。

### MRZ 校验位恢复

MRZ 校验位使用权重 7-3-1 的循环校验算法。字母 A-Z 映射为 10-35，`<` 映射为 0：

```python
_WEIGHTS = (7, 3, 1)

def mrz_value(ch: str) -> int:
    if ch.isdigit():
        return int(ch)
    if "A" <= ch <= "Z":
        return ord(ch) - ord("A") + 10
    if ch == "<":
        return 0
    raise ValueError(f"unsupported MRZ character: {ch!r}")

def mrz_check_digit(field: str) -> str:
    total = sum(mrz_value(c) * _WEIGHTS[i % 3] for i, c in enumerate(field))
    return str(total % 10)
```

对 `"111116"` 计算校验位得到 `"7"`，补全后的 MRZ 行为：

```text
12345678<8<<<1110182<1111167<<<<<<<<<<<<<<<4
```

### BAC 密钥派生

BAC（Basic Access Control）协议的密钥派生过程如下：

1. 从 MRZ 第二行提取 `MRZ_information`：出生日期（含校验位）+ 有效期（含校验位）+ 证件编号
2. 计算 `K_seed = SHA1(MRZ_information)[:16]`
3. 计算 `K_ENC = SHA1(K_seed + 0x00000001)[:16]`，然后做奇偶校验调整（DES/AES 密钥要求每字节具有奇数个 1）

```python
mrz_info = mrz_line[0:10] + mrz_line[13:20] + mrz_line[21:28]  # 25 字符

def adjust_odd_parity(data: bytes) -> bytes:
    result = bytearray()
    for b in data:
        candidate = b & 0xFE  # 清除最低位
        if candidate.bit_count() % 2 == 0:
            candidate |= 1     # 确保奇数个 1
        result.append(candidate)
    return bytes(result)

key_seed = sha1(mrz_info.encode("ascii")).digest()[:16]
kenc = adjust_odd_parity(sha1(key_seed + b"\x00\x00\x00\x01").digest()[:16])
```

### 解密

拿到 `K_ENC` 后，密文以 AES-CBC 模式（零 IV）解密，并使用 01-00 去填充算法（找到 `\x01` 标记并截断之前的内容）：

```python
def one_zero_unpad(data: bytes) -> bytes:
    idx = len(data) - 1
    while idx >= 0 and data[idx] == 0:
        idx -= 1
    if idx < 0 or data[idx] != 1:
        raise ValueError("invalid 01-00 padding")
    return data[:idx]
```

最终恢复出的 codeword 为：

```text
Kryptographie!
```

这个题目最有价值的不是 AES 解密本身，而是看到了真实系统（电子护照 BAC 协议）中的密钥派生流程：密钥来自护照上印刷的可见信息（MRZ），这意味着任何人只要物理接触过护照，就能计算出 BAC 密钥。BAC 的设计意图本就不是防止物理接触者，而是防止远程的非接触式（RFID）窃听——即使攻击者截获了 RFID 通信，如果没有事先看到护照上的 MRZ 信息，就无法解密通信内容。

## 小结

这次实验从 PKCS#7 填充开始，逐步深入到 ECB 和 CBC 两种分组密码模式的安全分析。几个重要的体会是：

- **ECB 的安全性缺陷从原理上就注定了**。它不是随机化的加密方案，相同的明文块产生相同的密文块。这导致三种实战攻击：模式检测（通过重复块鉴别）、逐字节解密（利用输入控制能力逐位恢复秘密）、剪切粘贴（密文块级别的替换实现权限提升）。
- **CBC 掩盖了 ECB 的"重复块"问题，但引入了新的漏洞**。CBC 的链式结构让每个密文块依赖于前一个块，攻击者虽然不能直接知道明文内容，但可以通过翻转前一密文块来精确控制当前块的解密结果。这说明加密和认证是两回事——机密性不能替代完整性。
- **随机前缀（Challenge 14 中的做法）不能从根本上修复 ECB**。它只是增加了对齐的成本，但攻击仍以几乎相同的复杂度完成。要防御这些攻击，不应该是给 ECB 打补丁，而是根本不使用 ECB。
- **BAC 密钥派生展示了侧信道信息如何缩小搜索空间**。MRZ 的有限字符集和已知结构让密钥空间从"不可能枚举"变成了"可以直接计算"。
- **填充函数的设计直接影响安全性**。PKCS#7 填充和 01-00 填充虽然在格式上不同，但核心意图一致：提供确定的边界标记。如果去填充时不严格验证，就会打开 padding oracle 攻击的通道。

从这个角度看，现代密码学实验二不只是实现 AES 的两种工作模式，更重要的是理解加密模式的"完整性缺失"问题，以及如何利用密文的结构特征来绕过看似安全的边界。
