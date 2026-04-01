---
title: New Year CTF 2026 RE Writeup
published: 2026-04-01
description: "Challenges I wrote for a small New Year CTF."
image: ""
tags:
  - CTF
  - Reverse Engineering
category: "Write Up"
draft: false
lang: en
---

I wrote two reverse engineering challenges for a small New Year CTF.

## nonogram

The core idea was to encode the flag as a nonogram. To force a unique solution, I added a `crc32` check. It feels a bit pointless, but I did not know a better way to control uniqueness.

There is also a small trap: the nonogram clues are loaded in `.init`.

```python
#!/usr/bin/env python3
import argparse
import subprocess
from functools import lru_cache


WIDTH = 0x113  # 275
HEIGHT = 5
BIT_BUDGET = 0xFE5  # 4069 bits consumed by verifier

# Derived from reversing nonogram_gate
CIPHER_FILE_OFFSET = 0x2020
CIPHER_LEN = 0x1FD  # 509
XOR_STRIDE = 0x3D


def extract_cipher(path: str) -> bytes:
    with open(path, "rb") as f:
        blob = f.read()
    end = CIPHER_FILE_OFFSET + CIPHER_LEN
    if end > len(blob):
        raise ValueError("binary too small for expected encrypted clue region")
    return blob[CIPHER_FILE_OFFSET:end]


def decode_clue_blob(cipher: bytes) -> bytes:
    tmp = bytearray(CIPHER_LEN)
    out = bytearray(CIPHER_LEN)
    for i, c in enumerate(cipher):
        tmp[i] = (c ^ ((i * XOR_STRIDE - 0x0D) & 0xFF)) & 0xFF
    for i, v in enumerate(tmp):
        out[(i * 7) % CIPHER_LEN] = v
    return bytes(out)


class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.bitpos = 0

    def read(self, nbits: int) -> int:
        val = 0
        for _ in range(nbits):
            if self.bitpos >= len(self.data) * 8:
                raise ValueError("bitstream underflow")
            byte = self.data[self.bitpos // 8]
            shift = 7 - (self.bitpos % 8)
            bit = (byte >> shift) & 1
            val = (val << 1) | bit
            self.bitpos += 1
        return val


def parse_clues(decoded: bytes):
    br = BitReader(decoded)
    row_clues = []
    for _ in range(HEIGHT):
        cnt = br.read(7)
        row_clues.append([br.read(3) for _ in range(cnt)])

    col_clues = []
    for _ in range(WIDTH):
        cnt = br.read(7)
        col_clues.append([br.read(3) for _ in range(cnt)])

    if br.bitpos != BIT_BUDGET:
        raise ValueError(f"unexpected clue bit count: {br.bitpos} != {BIT_BUDGET}")
    return row_clues, col_clues


def runs_from_bits(bits):
    runs = []
    run = 0
    for b in bits:
        if b:
            run += 1
        elif run:
            runs.append(run)
            run = 0
    if run:
        runs.append(run)
    return runs


def column_candidates(col_clues):
    cand = []
    for clue in col_clues:
        valid = []
        for mask in range(1 << HEIGHT):
            bits = [1 if (mask >> r) & 1 else 0 for r in range(HEIGHT)]
            if runs_from_bits(bits) == clue:
                valid.append(bits)
        if not valid:
            raise ValueError(f"no candidate column for clue {clue}")
        cand.append(valid)
    return cand


def row_transition_table(row_clues):
    tables = []
    starts = []
    accepts = []
    for runs in row_clues:
        k = len(runs)
        state_id = {}
        states = []
        trans = []

        def intern(st):
            if st in state_id:
                return state_id[st]
            idx = len(states)
            state_id[st] = idx
            states.append(st)
            trans.append([-1, -1])
            return idx

        start = intern((0, 0, 0))  # (next_run_idx, rem_in_current_run, must_gap_zero)
        q = [start]
        qi = 0
        while qi < len(q):
            sid = q[qi]
            qi += 1
            run_idx, rem, must_gap = states[sid]
            for bit in (0, 1):
                nxt = None
                if rem > 0:
                    if bit == 1:
                        rem2 = rem - 1
                        if rem2 == 0:
                            if run_idx == k - 1:
                                nxt = (k, 0, 0)
                            else:
                                nxt = (run_idx + 1, 0, 1)
                        else:
                            nxt = (run_idx, rem2, 0)
                else:
                    if run_idx == k:
                        if bit == 0:
                            nxt = (k, 0, 0)
                    else:
                        if must_gap:
                            if bit == 0:
                                nxt = (run_idx, 0, 0)
                        else:
                            if bit == 0:
                                nxt = (run_idx, 0, 0)
                            else:
                                rem2 = runs[run_idx] - 1
                                if rem2 == 0:
                                    if run_idx == k - 1:
                                        nxt = (k, 0, 0)
                                    else:
                                        nxt = (run_idx + 1, 0, 1)
                                else:
                                    nxt = (run_idx, rem2, 0)
                if nxt is not None:
                    nid = intern(nxt)
                    trans[sid][bit] = nid
                    if nid >= len(q):
                        q.append(nid)

        accept_set = {sid for sid, (ri, rem, _) in enumerate(states) if ri == k and rem == 0}
        tables.append(trans)
        starts.append(start)
        accepts.append(accept_set)
    return tables, starts, accepts


def solve_board(row_clues, col_clues):
    col_cands = column_candidates(col_clues)
    trans, starts, accepts = row_transition_table(row_clues)

    @lru_cache(maxsize=None)
    def dfs(col, s0, s1, s2, s3, s4):
        states = (s0, s1, s2, s3, s4)
        if col == WIDTH:
            ok = all(states[r] in accepts[r] for r in range(HEIGHT))
            return tuple() if ok else None

        for bits in col_cands[col]:
            nxt = []
            valid = True
            for r in range(HEIGHT):
                ns = trans[r][states[r]][bits[r]]
                if ns < 0:
                    valid = False
                    break
                nxt.append(ns)
            if not valid:
                continue
            tail = dfs(col + 1, nxt[0], nxt[1], nxt[2], nxt[3], nxt[4])
            if tail is not None:
                return (tuple(bits),) + tail
        return None

    path = dfs(0, starts[0], starts[1], starts[2], starts[3], starts[4])
    if path is None:
        raise ValueError("no satisfying board found")

    board = [[0] * WIDTH for _ in range(HEIGHT)]
    for c, col_bits in enumerate(path):
        for r in range(HEIGHT):
            board[r][c] = col_bits[r]
    return board


def board_to_submission_hex(board):
    bits = []
    for r in range(HEIGHT):
        bits.extend(board[r])
    bits.append(0)  # parser expects one extra trailing bit from 344th nibble; must be zero

    if len(bits) != 0x560:  # 1376
        raise ValueError("unexpected bit length for hex encoding")

    out = []
    for i in range(0, len(bits), 4):
        nib = (bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3]
        out.append(format(nib, "x"))
    return "".join(out)


def pretty(board):
    return "\n".join("".join("#" if board[r][c] else "." for c in range(WIDTH)) for r in range(HEIGHT))


def main():
    ap = argparse.ArgumentParser(description="Solve nonogram_gate by decoding and solving its nonogram clues.")
    ap.add_argument("binary", nargs="?", default="./nonogram_gate", help="path to challenge binary")
    ap.add_argument("--run", action="store_true", help="run the binary with computed hex")
    args = ap.parse_args()

    cipher = extract_cipher(args.binary)
    decoded = decode_clue_blob(cipher)
    row_clues, col_clues = parse_clues(decoded)
    board = solve_board(row_clues, col_clues)
    answer_hex = board_to_submission_hex(board)

    print(answer_hex)
    print()
    print(pretty(board))

    if args.run:
        p = subprocess.run(
            [args.binary],
            input=(answer_hex + "\n").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        print()
        print(p.stdout.decode(errors="replace"))


if __name__ == "__main__":
    main()
```

## starless_c

I mean it, this is basically the [original challenge](https://github.com/uclaacm/lactf-archive/tree/main/2026/rev/starless-c).

The underlying logic is just Sokoban with WASD movement and `F` for checking the result, except here you are pushing memory blocks. Since there are only a few boxes, a bitmask BFS solves it very quickly. I was lazy here, so I just pasted the author's original source code.

```python
from copy import deepcopy

puzzle = """
########
#..#####
#.....##
#oo.oo##
#..#o..#
#......#
########
""".strip().split("\n")
puzzle = [list(x) for x in puzzle]

pos = (1, 1)

inp = ""
history = []
while True:
    print(inp)
    for (i, r) in enumerate(puzzle):
        for (j, v) in enumerate(r):
            x = v
            if (i, j) == pos:
                x = "x"
            print(x, end="")
        print()
    for c in input("> "):
        if c == "z":
            (puzzle, pos, inp) = history.pop()
            continue
        elif c in ("w", "a", "s", "d"):
            (dr, dc) = {"w": (-1, 0), "s": (1, 0), "a": (0, -1), "d": (0, 1)}[c]
            (nr, nc) = (pos[0] + dr, pos[1] + dc)
            hist = (deepcopy(puzzle), pos, inp)
            if puzzle[nr][nc] == "#":
                continue
            if puzzle[nr][nc] == "o":
                (nnr, nnc) = (nr + dr, nc + dc)
                if puzzle[nnr][nnc] != ".":
                    continue
                puzzle[nnr][nnc] = "o"
                puzzle[nr][nc] = "."
            pos = (nr, nc)
            history.append(hist)
            inp += c
        else:
            print("unknown")
```
