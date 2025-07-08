---
title: 'WannaGame Championship 2024'
date: 2024-12-16 00:00:00 +0700
categories: [CTF Write-up]
tags: [RSA, AES]
published: true
description: "Write-up for WannaGame Championship 2024"
---

Vừa qua mình đã thử sức với WannaGame Championship 2024 và mình đã solve được 2 bài Crypto.

## random
### Challenge

![image](https://hackmd.io/_uploads/rJQkZ-2VJe.png)

Souce Code:
```python
import random

random.seed(random.randint(0, 10000))
flag = [c for c in open("flag.txt", "rb").read()]
for _ in range(1337):
  flag = [x ^ y for x, y in zip(flag, [random.randint(0, 255) for _ in range(len(flag))])]
print(bytes(flag).hex())

# 0203e2c0dd20182bea1d00f41b25ad314740c3b239a32755bab1b3ca1a98f0127f1a1aeefa15a418e9b03ad25b3a92a46c0f5a6f41cb580f7d8a3325c76e66b937baea
```

### Solution
Khởi đầu với một bài very easy. Ta biết được rằng, khi đã có $seed$ thì các chuỗi random tạo ra sẽ luôn giống nhau. Từ đó, ta sẽ bruteforce $seed$ và tìm flag.

Code:
```python
import random

ct = "0203e2c0dd20182bea1d00f41b25ad314740c3b239a32755bab1b3ca1a98f0127f1a1aeefa15a418e9b03ad25b3a92a46c0f5a6f41cb580f7d8a3325c76e66b937baea"
ct = bytes.fromhex(ct)

for seed in range(10000):
    random.seed(seed)
    flag = list(ct)

    for _ in range(1337):
        ran = [random.randint(0, 255) for _ in range(len(flag))]
        flag = [x ^ y for x, y in zip(flag, ran)]

    flag = bytes(flag)
    if b"W1{" in flag:
        print(flag)
        break

# W1{maybe_the_seed_is_too_small..._b32fe938a402c22144b9d6497fd5a709}
```

## ECB
### Challenge
![image](https://hackmd.io/_uploads/r15QGWhVJx.png)
Source Code:
```python
import gostcrypto
from secret import key
from Crypto.Util.Padding import pad

with open("flag.txt", "rb") as f:
    flag = bytearray(f.read())

try:
    plaintext = bytearray.fromhex(input("Plaintext (hex): "))
    plaintext = pad(plaintext + flag, 16)

    cipher = gostcrypto.gostcipher.new('kuznechik', key, gostcrypto.gostcipher.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    print(ciphertext.hex())
except:
    print("Eh!")
    exit(0)
```

### Solution
Ta nhận thấy rằng đây là dạng mã hóa `ECB`. Mà ta đã biết thì `ECB` sẽ tách plaintext ra thành các khối, mỗi khối gồm 16 bytes để mã hóa. Sau một vài phép thử thì mình biết được `len(flag) < 32`.

Ta nhận thấy rằng:
- Khi ta gửi `test = b'0' * 15` lên thì `plaintext = pad(test + flag, 16)` tức là trong block đầu tiên của ECB sẽ gồm `000000000000000W` (ta biết W1{ là tiền tổ của flag). Còn block thứ 2 sẽ là `1{.....`
- Và nếu ta gửi `test = b'0' * 15 + b'W'` lên thì block đầu tiên của ta cũng sẽ là `000000000000000W` nhưng block thứ 2 sẽ là `W1{.....`
- Dễ thấy được với 2 cách gửi thì khối đầu tiên luôn giống nhau -> sau khi mã hóa cũng sẽ giống nhau.

Từ đó ta có được thuật toán bruteforce từng kí tự của flag rồi check.
Code:
```python
from pwn import *
import string

char_set = set(string.ascii_letters + string.digits + "{}_@")

len_flag = 31
flag = b''
for i in range(len_flag):
    conn = remote("chall.w1playground.com", 24777)
    conn.recvuntil(": ")

    test = "0" * (len_flag - len(flag))
    test_encoded = test.encode()
    conn.sendline(test_encoded.hex())

    cur = conn.recvline()
    cur = bytes.fromhex(cur.decode())

    conn.close()

    for ch in char_set:
        conn = remote("chall.w1playground.com", 24777)
        conn.recvuntil(": ")

        newpat = test.encode() + flag + ch.encode()
        conn.sendline(newpat.hex())

        res = conn.recvline().decode()
        res = bytes.fromhex(res)

        conn.close()

        if cur[:len(newpat)] == res[:len(newpat)]:
            flag += ch.encode()
            break

    if flag[-1] == b"}":
        break

print()
print(flag)

# W1{0Ld_pr0bl3m_BUT_n3W_c1pher}
```


## RAS (sau giải)
Bài này thì mình đã làm được tầm 80% trong giải nhưng bị mắc ở một chỗ. Sau khi end giải thì mình có hỏi các anh thì mới biết được 1 kiến thức cơ bản mà mình không nghĩ đến :<

### Challenge
![image](https://hackmd.io/_uploads/rJPJDW3N1g.png)
Source code:
```python
from Crypto.Util.number import *
from secret import flag
import random

class RAS(object):
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = (p**3 - p)*(q**3 - q)

    def generate_e(self):
        e = random.randint(self.p * self.q, (self.p * self.q)**2)
        return e

    def encrypt(self, pt):
        e = self.generate_e()
        assert pt < self.n
        c = pow(pt, e, self.n)
        return e, c

flag1, flag2, flag3 = bytes_to_long(flag[:len(flag)//3]), bytes_to_long(flag[len(flag)//3:2*len(flag)//3]), bytes_to_long(flag[2*len(flag)//3:])

# shuffle it
m1 = flag1*flag2*flag3
m2 = flag1 + flag2 + flag3
m3 = flag1 * flag2 + flag2 * flag3 + flag3 * flag1

nbit = 256
menu = '''
Welcome to my RAS
1. Send primes
2. Get encrypted flag
'''

b = False
print(menu)
while True:
    try:
        choose = input('> ')
        if choose == '1':
            primes = input(f"Send me two {nbit}-bit strong primes, separated by comma: ")
            try:
                p, q = map(int, primes.strip().split(','))
            except:
                raise Exception("Invalid input")

            if (isPrime(p) and isPrime(q) and
                p != q and
                p.bit_length() == q.bit_length() == nbit):
                b = True
                ras = RAS(p, q)
            else:
                print("Primes not strong enough!")
        elif choose == '2':
            if b:
                print(ras.encrypt(m1))
                print(ras.encrypt(m2))
                print(ras.encrypt(m3))
            else:
                raise Exception("You must send strong primes first!!!")
        else:
            raise Exception("Invalid choice!!!")

    except Exception as e:
        print(f"Error: {str(e)}")
        break
```

### Solution
Việc chọn p, q và tính được phi khá đơn giản nên mình sẽ skip phần đó luôn.

Điểm mấu chốt của bài này, đã khiến mình làm không ra đó chính là $N$ là một số chẵn. Từ đó author có thể tạo ra các giá trị $m$ chẵn khiến cho việc decrypt bằng công thức RSA bình thường sẽ không được. `c^d = m^(ed) (mod N)` mà vì `gcd(m, N) > 1` nên ta không thể áp dụng định lý Euler (`=> m^(ed) khác m`).

Vậy với trường hợp gcd(m, N) > 1 thì ta làm thế nào ?

Đặt `g = gcd(m, N)`. Ta có:
$c^d \equiv m^{ed}$ $(mod$ $N)$ $\equiv (m' * g) ^ {ed}$ $(mod$ $N)$ $\equiv (m')^{ed} * g^{ed}$ $(mod$ $N)$
$\equiv m' * g^{ed}$ $(mod$ $N)$.
Vì biểu thức trên chỉ đúng với điều kiện `gcd(m', N) = 1` nên ta sẽ tìm các giá trị $m'$ bằng cách bruteforce giá trị $g$.

Từ đó bài toán của ta sẽ trở về thành: Bruteforce giá trị $g$. Tìm tất cả các giá trị $m'$ sao cho $g*m' \equiv c^d$ $(mod$ $N)$. Và $m' \in [0..N-1]$

Ta có:
- $Ax \equiv B$ $(mod$ $N)$ $<=>$ $Ax=B+Ny$ $<=>$ $Ax-Ny=B$ $(1)$
Ta thấy đây là [phương trình Diophantine tuyến tính](https://www.geeksforgeeks.org/linear-diophantine-equations/) nên điều kiện để có nghiệm của phương trình phải là $gcd(A,N)$ | $B$
- Theo Extended Euclid, ta sẽ tìm được $u, v$ sao cho:
$Au+Nv=gcd(A,N)=d$ $<=>$ $Au \equiv d$ $(mod$ $N)$ $(2)$
- Giả sử $B \% d = 0$. Do đó luôn tồn tại nghiệm của phương trình $(1)$. Nhân $\frac{B}{d}$ vào 2 vế của phương trình $(2)$ ta có: $Au * \frac{B}{d} \equiv d * \frac{B}{d}$ $(mod$ $N)$
$\Rightarrow Au * \frac{B}{d} \equiv B$ $(mod$ $N)$ $<=>$ $A * u\frac{B}{d} \equiv B$ $(mod$ $N)$ .
- Vậy $u\frac{B}{d}$ là một nghiệm của $(1)$.
- Gọi $x_0 = u\frac{B}{d}$. Do đó các nghiệm của phương trình $(1)$ sẽ là:
$x_0, x_0 + \frac{N}{d}, x_0+2\frac{N}{d},...,x_0+(d-1)\frac{N}{d}$.
- $x_0 + i\frac{N}{d}$ là nghiệm của $(1)$ bởi vì:
$\Rightarrow A(x_0+i\frac{N}{d})$ $mod$ $N$ = $(Ax_0 + A*i\frac{N}{d})$ $mod$ $N$ = $Ax_0$ $mod$ $N$.

Sau khi tìm được $m'$ thì ta sẽ tính được $m = g * m'$. Vậy, ta sẽ tìm được các giá trị $m_1, m_2, m_3$ khả thi. Từ đó thử với mỗi bộ 3 $m_1, m_2, m_3$ và giải phương trình bậc ba $x^3 - m_2.x^2 + m_3.x - m_1$ để tìm flag.

Code:
```python
from pwn import *
from Crypto.Util.number import *
from sage.all import *
import itertools

p = 110546454747203504006925729538023265156225304520988132722771250047696607274399
q = 69432444660353724912594441619180565122596810625659229683919790847518915561813
N = (p**3 - p)*(q**3 - q)
phi = 8130718311181529512023061937820198911824250577656859808220234200906934536574593002998439406567360340616588872082761396586369901175200281306229826359367416808716672544100675100778004339594396045911708929205724269740521522382094059853335398782101368420506241771196284270924708276195859621696139078700006880839569915571277371872103794764324997362673688435622070419864110256852465372308815637409824647991609263674448439608843405825808056538999591789771495781171200

def ExtendedEuclidAlgo(a, b):
    if a == 0 :
        return b, 0, 1
    gcd, x1, y1 = ExtendedEuclidAlgo(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def linearCongruence(A, B, N):
    A, B = A % N, B % N
    u, v = 0, 0
    d, u, v = ExtendedEuclidAlgo(A, N)

    res = []
    if (B % d != 0):
        return res

    x0 = (u * (B // d)) % N
    if x0 < 0:
        x0 += N
    for i in range(d):
        res.append((x0 + i * (N // d)) % N)

    return res

def find_m(e, c):
    m_possible = []
    d = inverse(e, phi)
    ct = pow(c, d, N)

    for gcd in range(1, 100):
        if N % gcd:
            continue
        roots = linearCongruence(pow(gcd, e*d, N), ct, N)
        for x in roots:
            m_possible.append((x * gcd) % N)
    return m_possible

conn = remote("154.26.136.227", 46352)
conn.recvuntil("> ")
conn.sendline("1")
conn.recvuntil(": ")
conn.sendline(str(p) + ", " + str(q))


m1, m2, m3 = [], [], []
while True:
    conn.recvuntil("> ")
    conn.sendline("2")
    data = conn.recvline()
    e1 = data.decode().strip().split(" ")[0]
    c1 = data.decode().strip().split(" ")[1]
    e1, c1 = int(e1[1:-1]), int(c1[:-1])

    data = conn.recvline()
    e2 = data.decode().strip().split(" ")[0]
    c2 = data.decode().strip().split(" ")[1]
    e2, c2 = int(e2[1:-1]), int(c2[:-1])

    data = conn.recvline()
    e3 = data.decode().strip().split(" ")[0]
    c3 = data.decode().strip().split(" ")[1]
    e3, c3 = int(e3[1:-1]), int(c3[:-1])

    if GCD(e1, phi) == 1:
        m1 = find_m(e1, c1)
    if GCD(e2, phi) == 1:
        m2 = find_m(e2, c2)
    if GCD(e3, phi) == 1:
        m3 = find_m(e3, c3)

    m1 = list(set(m1))
    m2 = list(set(m2))
    m3 = list(set(m3))
    print(len(m1), len(m2), len(m3))
    if len(m1) and len(m2) and len(m3):
        for x1, x2, x3 in itertools.product(m1, m2, m3):
            x = ZZ['x'].gen()
            fx = x**3 - x2*x**2 + x3*x - x1
            root = fx.roots()
            if len(root) == 3:
                flag = b""
                flag += long_to_bytes(int(root[2][0]))
                flag += long_to_bytes(int(root[1][0]))
                flag += long_to_bytes(int(root[0][0]))

                print(flag)
                exit()


# W1{wi3rd_ch41!En9e_n33d_4_WlErD_s0O!luti0n_6f339749663eeb3508c3b00c15872e41}
```