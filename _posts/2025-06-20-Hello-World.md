---
title: 'HTB: Cyber Apocalypse CTF 2025'
date: 2025-03-21 00:00:00 +0700
categories: [ctf]
tags: [Crypto]
published: true
description: "Write-up for HTB: Cyber Apocalypse CTF 2025"
---

Vừa qua mình có tham gia giải HTB: Cyber Apocalypse CTF 2025, đây là một số bài mình đã làm được trong giải.

## 1. Traces (very easy)
### Challenge:
Code server:
```python
from db import *
from Crypto.Util import Counter
from Crypto.Cipher import AES
import os
from time import sleep
from datetime import datetime

def err(msg):
    print('\033[91m'+msg+'\033[0m')

def bold(msg):
    print('\033[1m'+msg+'\033[0m')

def ok(msg):
    print('\033[94m'+msg+'\033[0m')

def warn(msg):
    print('\033[93m'+msg+'\033[0m')

def menu():
    print()
    bold('*'*99)
    bold(f"*                                🏰 Welcome to EldoriaNet v0.1! 🏰                                *")
    bold(f"*            A mystical gateway built upon the foundations of the original IRC protocol 📜        *")
    bold(f"*          Every message is sealed with arcane wards and protected by powerful encryption 🔐      *")
    bold('*'*99)
    print()

class MiniIRCServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.key = os.urandom(32)

    def display_help(self):
        print()
        print('AVAILABLE COMMANDS:\n')
        bold('- HELP')
        print('\tDisplay this help menu.')
        bold('- JOIN #<channel> <key>')
        print('\tConnect to channel #<channel> with the optional key <key>.')
        bold('- LIST')
        print('\tDisplay a list of all the channels in this server.')
        bold('- NAMES #<channel>')
        print('\tDisplay a list of all the members of the channel #<channel>.')
        bold('- QUIT')
        print('\tDisconnect from the current server.')

    def output_message(self, msg):
        enc_body = self.encrypt(msg.encode()).hex()
        print(enc_body, flush=True)
        sleep(0.001)

    def encrypt(self, msg):
        encrypted_message = AES.new(self.key, AES.MODE_CTR, counter=Counter.new(128)).encrypt(msg)
        return encrypted_message

    def decrypt(self, ct):
        return self.encrypt(ct)

    def list_channels(self):
        bold(f'\n{"*"*10} LIST OF AVAILABLE CHANNELS {"*"*10}\n')
        for i, channel in enumerate(CHANNELS.keys()):
            ok(f'{i+1}. #{channel}')
        bold('\n'+'*'*48)

    def list_channel_members(self, args):
        channel = args[1] if len(args) == 2 else None

        if channel not in CHANNEL_NAMES:
            err(f':{self.host} 403 guest {channel} :No such channel')
            return

        is_private = CHANNELS[channel[1:]]['requires_key']
        if is_private:
            err(f':{self.host} 401 guest {channel} :Unauthorized! This is a private channel.')
            return

        bold(f'\n{"*"*10} LIST OF MEMBERS IN {channel} {"*"*10}\n')
        members = CHANNEL_NAMES[channel]
        for i, nickname in enumerate(members):
            print(f'{i+1}. {nickname}')
        bold('\n'+'*'*48)

    def join_channel(self, args):
        channel = args[1] if len(args) > 1 else None

        if channel not in CHANNEL_NAMES:
            err(f':{self.host} 403 guest {channel} :No such channel')
            return

        key = args[2] if len(args) > 2 else None

        channel = channel[1:]
        requires_key = CHANNELS[channel]['requires_key']
        channel_key = CHANNELS[channel]['key']

        if (not key and requires_key) or (channel_key and key != channel_key):
            err(f':{self.host} 475 guest {channel} :Cannot join channel (+k) - bad key')
            return

        for message in MESSAGES[channel]:
            timestamp = message['timestamp']
            sender = message['sender']
            print(f'{timestamp} <{sender}> : ', end='')
            self.output_message(message['body'])

        while True:
            warn('You must set your channel nickname in your first message at any channel. Format: "!nick <nickname>"')
            inp = input('guest > ').split()
            if inp[0] == '!nick' and inp[1]:
                break

        channel_nickname = inp[1]
        while True:
            timestamp = datetime.now().strftime('%H:%M')
            msg = input(f'{timestamp} <{channel_nickname}> : ')
            if msg == '!leave':
                break

    def process_input(self, inp):
        args = inp.split()
        cmd = args[0].upper() if args else None

        if cmd == 'JOIN':
            self.join_channel(args)
        elif cmd == 'LIST':
            self.list_channels()
        elif cmd == 'NAMES':
            self.list_channel_members(args)
        elif cmd == 'HELP':
            self.display_help()
        elif cmd == 'QUIT':
            ok('[!] Thanks for using MiniIRC.')
            return True
        else:
            err('[-] Unknown command.')


server = MiniIRCServer('irc.hackthebox.eu', 31337)

exit_ = False
while not exit_:
    menu()
    inp = input('> ')
    exit_ = server.process_input(inp)
    if exit_:
        break

```

### Solution:
Phân tích code một chút: code này mô phỏng lại một server gồm các tính năng như `JOIN`, `LIST`, `NAMES`, `QUIT` với các tin nhắn được `encrypt` bằng `AES-CTR`.
Sau khi mình thử các tính năng của server:

![image](https://hackmd.io/_uploads/rkicpt0hyx.png)

![image](https://hackmd.io/_uploads/rJqjaYA21e.png)

Ta thấy được có 2 `channels` trong server này là `#general` và `#secret`. Vì channel `#general` không cần `key` nên mình đã vào xem thử.

![image](https://hackmd.io/_uploads/Hk4kAtRhkx.png)

Đây là một cuộc hội thoại giữa 3 nhân vật, các tin nhắn này đã được mã hóa `AES-CTR` như phân tích trên. Bây giờ mình phải làm thế nào để đọc được tin nhắn gốc ?

Mấu chốt của bài này nằm ở đây: ![image](https://hackmd.io/_uploads/SyMrRYA3yl.png)
Vì `AES-CTR` mà một loại `stream cipher` tức là nó sử dụng `counter` để tạo thành `key_stream` sau đó `XOR` với `plaintext` để lấy `ciphertext`. Mà trong code này, ta thấy `counter` đều được reset là `counter = Counter.new(128)` suy ra mỗi lần `encrypt` ta đều sử dụng cùng 1 `keystream`. Ta có:
```
C1 = key_stream ^ P1
C2 = key_stream ^ P2
=> C1 ^ C2 = P1 ^ P2
```
Vậy nếu như ta biết được `P1` thì ta sẽ tìm được `P2`.
Giờ ta quay lại vấn đề giải mã các đoạn tin nhắn kia. Ta thấy 3 tin nhắn cuối y chang nhau và ta đã biết đó là `!leave`. => Ta có được 6 kí tự đầu tiên của `key_stream`. Lấy `key_stream` XOR với các tin nhắn mã hóa trên và xem điều gì sẽ xảy ra.

![image](https://hackmd.io/_uploads/ByU--9C3yx.png)

Đúng như ta đã phân tích. Khi có được `key_stream` rồi thì ta hoàn toàn có thể recover lại các tin nhắn gốc. Đến đây thì cách làm sẽ là đoán từng kí tự tiếng anh của `plaintext` sau đó tính `key_stream` rồi lại đem nó XOR với các `ciphertext`.


Code:
```python
from pwn import *

def XOR(a, b):
    res = b""
    for i in range(min(len(a), len(b))):
        res += bytes([a[i] ^ b[i]])
    return res

io = remote("94.237.55.186", 51601)
io.sendafter(b"> ", b"JOIN #general\n")

ct = []
for _ in range(21):
    io.recvuntil(b"> : ")
    ct.append(io.recvline().strip().decode())


for i in range(len(ct)):
    ct[i] = bytes.fromhex(ct[i])

pt = b"!leave"
keystream = XOR(ct[20], pt)

for i in range(len(ct)):
    print(XOR(ct[i], keystream), i)
```

Code này thì mình chỉ cần thay một `plaintext` đã biết được vào biến `pt` rồi tiếp tục quan sát và thay đổi. Sau khi giải mã được các tin nhắn thì đây là các tin nhắn gốc:
```
b'!nick Doomfang'
b'!nick Stormbane'
b'!nick Runeblight'
b"We've got a new tip about the rebels. Let's keep our chat private."
b'Understood. Has there been any sign of them regrouping since our last move?'
b"Not yet, but I'm checking some unusual signals. If they sense us, we might have to c"
b"This channel is not safe for long talks. Let's switch to our private room."
b'Here is the passphrase for our secure channel: %mi2gvHHCV5f_kcb=Z4vULqoYJ&oR'
b'Got it. Only share it with our most trusted allies.'
b'Yes. Our last move may have left traces. We must be very careful.'
b"I'm checking our logs to be sure no trace of our actions remains."
b"Keep me updated. If they catch on, we'll have to act fast."
b"I'll compare the latest data with our backup plan. We must erase any sign we were he"
b'If everything is clear, we move to the next stage. Our goal is within reach.'
b"Hold on. I'm seeing strange signals from outside. We might be watched."
b"We can't take any risks. Let's leave this channel before they track us."
b'Agreed. Move all talks to the private room. Runeblight, please clear the logs here.'
b"Understood. I'm disconnecting now. If they have seen us, we must disappear immediate"
b'!leave'
b'!leave'
b'!leave'
```

Và mình đã tìm thấy `key = %mi2gvHHCV5f_kcb=Z4vULqoYJ&oR` để vào channel `#secret`.
![image](https://hackmd.io/_uploads/SkikGc0hJe.png)
Trong `#secret` cũng giống như `#general`, mình cũng dùng cách như trên để giải mã tin nhắn gốc.

Code:
```python
from pwn import *

def XOR(a, b):
    res = b""
    for i in range(min(len(a), len(b))):
        res += bytes([a[i] ^ b[i]])
    return res

io = remote("94.237.55.186", 51601)
# io.sendafter(b"> ", b"JOIN #general\n")

key = "%mi2gvHHCV5f_kcb=Z4vULqoYJ&oR"
io.sendafter(b"> ", b"JOIN #secret " + key.encode() + b'\n')
io.recvline()

ct = []
for _ in range(15):
    io.recvuntil(b"> : ")
    ct.append(io.recvline().strip().decode())


for i in range(len(ct)):
    ct[i] = bytes.fromhex(ct[i])

pt = b"!leave"
keystream = XOR(ct[14], pt)

for i in range(len(ct)):
    print(XOR(ct[i], keystream), i)
```
Sau khi giải mã thì đây là các tin nhắn gốc:
```
b'!nick Stormbane'
b'!nick Runeblight'
b'We should keep our planning here. The outer halls are not secure, and too many eyes watch the open channels.'
b"Agreed. The enemy's scouts grow more persistent. If they catch even a whisper of our designs, they will move against us. We must not allow their seers or spies to track our steps."
b"I've been studying the traces left behind by our previous incantations, and something feels wrong. Our network of spells has sent out signals to an unknown beacon-one that none of "
b"I'm already cross-checking our spellwork against the ancient records. If this beacon was part of an older enchantment, I'll find proof. But if it is active now, then we have a prob"
b"We cannot afford hesitation. If this is a breach, then the High Council's forces may already be on our trail. Even the smallest mistake could doom our entire campaign. We must conf"
b'Exactly. And even if we remain unseen for now, we need contingency plans. If the Council fortifies its magical barriers, we could lose access to their strongholds. Do we have a sec'
b'Yes, but we must treat it only as a last resort. If we activate it too soon, we risk revealing its location. It is labeled as: HTB{Crib_Dragging_Exploitation_With_Key_Nonce_Reuse!}'
b'Good. No record of it must exist in the written tomes. I will ensure all traces are erased, and it shall never be spoken of openly. If the enemy ever learns of it, we will have no '
b'Agreed. The more we discuss it, the greater the risk. Every moment we delay, the Council strengthens its defenses. We must act soon before our window of opportunity closes.'
b'We should end this meeting and move to a more secure sanctum. If their mages or spies are closing in, they may intercept our words. We must not take that chance. Let this be the la'
b'!leave'
b'!leave'
b'!leave'
```

`Flag = HTB{Crib_Dragging_Exploitation_With_Key_Nonce_Reuse!}`

## 2. Kewiri (very easy)
### Challenge:
![image](https://hackmd.io/_uploads/HkY-XqRh1x.png)

### Solution:
Bài này, ta phải tương tác với server và trả lời các câu hỏi.

#### Câu 1:

![image](https://hackmd.io/_uploads/SkaIIc0nJg.png)

Với số nguyên tố `p=21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061`. Hỏi `p` có bao nhiêu bit ?

**Answer:**
Dùng hàm `bit_length()` của python ta có `p.bit_length() = 384`
Code:
```python
""" QUESTION 1 """
io.sendafter(b"[1] How many bits is the prime p? > ", str(p.bit_length()).encode() + b"\n")
```


#### Câu 2:

![image](https://hackmd.io/_uploads/ByJVwc03Jx.png)

Hãy factor `order` của nhóm nhân trong trường hữu hạn `F_p`.

**Answer:**
Vì `p` là một số nguyên tố, nên `order` của `F_p` chính là `p - 1`. Factor `p - 1` ta được
`answer2="2,2_5,1_635599,1_2533393,1_4122411947,1_175521834973,1_206740999513,1_1994957217983,1_215264178543783483824207,1_10254137552818335844980930258636403,1"`

Code:
```python
""" QUESTION 2 """
# p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
# prs = factor(p - 1)
# pr = [val[0] for val in prs]
# test2 = ""
# for p, e in prs:
#     test2 += str(p) + "," + str(e) + "_"
# test2 = test2[:-1]
answer2 = "2,2_5,1_635599,1_2533393,1_4122411947,1_175521834973,1_206740999513,1_1994957217983,1_215264178543783483824207,1_10254137552818335844980930258636403,1"
io.sendafter(b'[2] Enter the full factorization of the order of the multiplicative group in the finite field F_p in ascending order of factors (format: p0,e0_p1,e1_ ..., where pi are the distinct factors and ei the multiplicities of each factor) > ', answer2.encode() + b"\n")

```

#### Câu 3:

![image](https://hackmd.io/_uploads/rkzi_c021x.png)

Ở câu này, server cho ta 17 số và yêu cầu ta trả lời `1` nếu số đó là một `generator` của `F_p` ngược lại trả lời `0`.

**Answer:**
Ta đã biết, trong $\mathbb{F}_p^*$ (p là nguyên tố), nếu $g$ là một generator đồng nghĩa với việc $g^k \bmod p$ có thể sinh ra tất cả các số từ $1$ đến $p-1$.

Tương đương với việc $g$ có bậc là $p-1$: $\operatorname{ord}_p(g) = p - 1$.

Do $\mathbb{F}_p^*$ là một nhóm cyclic bậc $p-1$, mọi phần tử trong nhóm đều có bậc là một **ước số** của $p-1$.

Nếu $g$ không phải là generator thì bậc của $g$ sẽ nhỏ hơn $p-1$ và chia hết cho một số $d$ là ước của $p-1$.

Vậy, ta sẽ kiểm tra $g$ có phải là generator không bằng cách kiểm tra nếu tồn tại một số $d \mid (p-1)$ sao cho $g^{(p-1)/d} \equiv 1 \pmod p$ thì $g$ không phải là **generator**.


Code:
```python
""" QUESTION 3 """
def is_generator(g, p, factors):
    for prime in factors:
        if pow(g, (p - 1) // prime, p) == 1:
            return 0
    return 1

# p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
# pr = [val[0] for val in factor(p - 1)]
pr = [2, 5, 635599, 2533393, 4122411947, 175521834973, 206740999513, 1994957217983, 215264178543783483824207, 10254137552818335844980930258636403]

io.recvuntil(b'[3] For this question, you will have to send 1 if the element is a generator of the finite field F_p, otherwise 0.\n')
for _ in range(17):
    g = int(io.recvuntil(b"?").decode()[:-1])
    io.sendafter(b" > ", str(is_generator(g, p, pr)).encode() + b'\n')
```


#### Câu 4:

![image](https://hackmd.io/_uploads/BkBiljAhye.png)

Cho $a, b$, hỏi `order` của đường cong Elliptic được xác định trên $\mathbb{F}_p^*$ là gì ?

**Answer:**
Câu này mình đã dùng hàm có sẵn của `sagemath`. Và nhận thấy một điều rằng `order_p = p` tức là đây là đường cong Elliptic dị thường (Anomalous Elliptic Curve).

Code:
```python
""" QUESTION 4 """
from sage.all import *
a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
E = EllipticCurve(GF(p), [a, b])
print(E.order())
ord_p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
io.sendafter(b"[4] What is the order of the curve defined over F_p? > ", str(ord_p).encode() + b'\n')
```

#### Câu 5:

![image](https://hackmd.io/_uploads/B1nNmjR3yg.png)

Hãy factor `order` của đường cong Elliptic được xác định trên trường hữu hạn $\mathbb{F}_{p^3}^*$.

**Answer:**
Câu này mình làm y chang như câu 4, chỉ thay đổi một chút ở `GF(p**3)`. Rồi dùng tool [factor.db](https://factordb.com/index.php?query=9547468349770605965573984760817208987986240857800275642666264260062210623470017904319931275058250264223830562439645572562493214488086970563135688265933076141657703804791593446020774169988605421998202682898213433784381043211278976059744771523119218399190407965593665262490269084642700982261912090274007278407746985341700600062580644280196871035164) để phân tích thừa số nguyên tố.

Code:
```python
""" QUESTION 5 """
from sage.all import *
a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
E = EllipticCurve(GF(p**3, 'x'), [a, b])
ord_E = E.order()
print(ord_E)
answer5 = "2,2_7,2_21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061,1_2296163171090566549378609985715193912396821929882292947886890025295122370435191839352044293887595879123562797851002485690372901374381417938210071827839043175382685244226599901222328480132064138736290361668527861560801378793266019,1"
io.sendafter(b'[5] Enter the full factorization of the order of the elliptic curve defined over the finite field F_{p^3}. Follow the same format as in question 2 > ', answer5.encode() + b'\n')
```

#### Câu 6:

![image](https://hackmd.io/_uploads/B1AP3jAhyx.png)

Hãy tìm giá trị $d$ biết $A = d * G$ với $A, G$ là 2 điểm nằm trên đường cong Elliptic trong trường $\mathbb{F}_p^*$.

**Answer:**
Đây là một bài toán ECDLP (Elliptic Curve Discrete Logarithm Problem). Bài toán này được phát biểu như sau:
Cho một đường cong Elliptic $E$ trên trường hữu hạn $\mathbb{F}_p$, một điểm cơ sở $P \in E(\mathbb{F}_p)$ và một điểm khác $Q \in <P>$, tìm số nguyên $k$ sao cho:
\begin{equation}
Q = kP
\end{equation} trong đó, phép nhân $kP$ là phép cộng lặp lại điểm $P$ trên đường cong Elliptic.

Mình chưa tìm hiểu sâu về ECC, nên câu này mình đã osint ra được [bài viết này](https://ctftime.org/writeup/29702). Như mình đã nói ở trên, đường cong Elliptic trong $\mathbb{F}_p$ là đường cong dị thường (anomalous curve) nên có một thuật toán giải quyết bài toán ECDLP trên đường cong dị thường đó là `Smart attack`. Vì mình chưa hiểu bản chất nên mình sẽ không viết ở đây.

Code:
```python
""" QUESTION 6 """
a = 408179155510362278173926919850986501979230710105776636663982077437889191180248733396157541580929479690947601351140
b = 8133402404274856939573884604662224089841681915139687661374894548183248327840533912259514444213329514848143976390134
p = 21214334341047589034959795830530169972304000967355896041112297190770972306665257150126981587914335537556050020788061
io.recvuntil(b"G has x-coordinate: ")
xG = int(io.recvline().strip().decode())
io.recvuntil(b"A has x-coordinate: ")
xA = int(io.recvline().strip().decode())

rhs_G = (xG**3 + a * xG + b) % p
yG = GF(p)(rhs_G).sqrt()

rhs_A = (xA**3 + a * xA + b) % p
yA = GF(p)(rhs_A).sqrt()

E = EllipticCurve(GF(p), [a, b])
G = E([xG, yG])
A = E([xA, yA])

assert p == E.order()

# https://ctftime.org/writeup/29702
def SmartAttack(P,Q,p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 2), [ ZZ(t) + randint(0,p)*p for t in E.a_invariants() ])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P,y_P = p_times_P.xy()
    x_Q,y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)

d = SmartAttack(G, A, p)

io.sendafter(b"[6] What is the value of d? > ", str(d).encode() + b'\n')
io.recvall()

```

Kết hợp tất cả các phần lại để có code hoàn chỉnh và lấy `flag`.

## 3. Prelim (easy)
### Challenge:
Source:
```python
from random import shuffle
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

n = 0x1337
e = 0x10001

def scramble(a, b):
    return [b[a[i]] for i in range(n)]

def super_scramble(a, e):
    b = list(range(n))
    while e:
        if e & 1:
            b = scramble(b, a)
        a = scramble(a, a)
        e >>= 1
    return b

message = list(range(n))
shuffle(message)

scrambled_message = super_scramble(message, e)

flag = pad(open('flag.txt', 'rb').read(), 16)

key = sha256(str(message).encode()).digest()
enc_flag = AES.new(key, AES.MODE_ECB).encrypt(flag).hex()

with open('tales.txt', 'w') as f:
    f.write(f'{scrambled_message = }\n')
    f.write(f'{enc_flag = }')
```

### Solution:
Sau khi phân tích code thì mình nhận thấy kết quả `message` của ta sẽ là một hoán vị của các số từ `1 -> n`. Lí do là cả 2 hàm `scramble và super_scramble` đều trả về kết quả là một hoán vị. Cộng thêm việc hàm `super_scramble` thực chất là một hàm lũy thừa tính `a ^ e` suy ra đây là một [nhóm đối xứng](https://en.wikipedia.org/wiki/Symmetric_group).

Vì các giá trị trong nhóm đối xứng đều là các hoán vị từ `1 -> n` nên số lượng giá trị trong nhóm (hay còn gọi là bậc của nhóm) sẽ là `order = n!`.

Ta có: `scrambled_message = message ^ e` nhìn vào phép toán này mình liền nghĩ ngay đến RSA. Tính `d = pow(e, -1, order) => ed = 1 (mod order)`
`=> message = scrambled_message ^ d = message ^ ed`

**Note**: Thực ra trong RSA, ta làm việc trên **nhóm nhân modulo N**, tức là:
\begin{equation}
\mathbb{Z}_N^* = \{ x | 1 \le x < N, gcd(x, N) = 1 \}
\end{equation} Bậc của nhóm này chính là $order = \phi(N)$ là số lượng phần tử trong nhóm.

Code:
```python
import ast
from hashlib import *
from Crypto.Cipher import AES
from math import lcm

n = 0x1337
e = 0x10001

with open('/home/team/CodePy/Cyber Apocalypse CTF 2025: Tales from Eldoria/Prelim/tales.txt', 'r') as f:
    scrambled_message = ast.literal_eval(f.readline().split('=')[1].strip())

enc_flag = "ca9d6ab65e39b17004d1d4cc49c8d6e82f9fa7419824d07096d41ee41f0578fe6835da78bc31dd46587a86377883e0b7"
enc_flag = bytes.fromhex(enc_flag)

def scramble(a, b):
    return [b[a[i]] for i in range(n)]

def super_scramble(a, e):
    b = list(range(n))
    while e:
        if e & 1:
            b = scramble(b, a)
        a = scramble(a, a)
        e >>= 1
    return b

order = 1
for i in range(1, n + 1):
    order *= i
message = super_scramble(scrambled_message, pow(e, -1, order))

key = sha256(str(message).encode()).digest()
flag = AES.new(key, AES.MODE_ECB).decrypt(enc_flag)

print(flag)

# HTB{t4l3s_fr0m___RS4_1n_symm3tr1c_gr0ups!}
```

## 4. Hourcle (easy)
### Challenge:
Source code:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os, string, random, re

KEY = os.urandom(32)

password = ''.join([random.choice(string.ascii_letters+string.digits) for _ in range(20)])

def encrypt_creds(user):
    padded = pad((user + password).encode(), 16)
    IV = os.urandom(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    ciphertext = cipher.decrypt(padded)
    return ciphertext

def admin_login(pwd):
    return pwd == password


def show_menu():
    return input('''
=========================================
||                                     ||
||   🏰 Eldoria's Shadow Keep 🏰       ||
||                                     ||
||  [1] Seal Your Name in the Archives ||
||  [2] Enter the Forbidden Sanctum    ||
||  [3] Depart from the Realm          ||
||                                     ||
=========================================

Choose your path, traveler :: ''')

def main():
    while True:
        ch = show_menu()
        print()
        if ch == '1':
            username = input('[+] Speak thy name, so it may be sealed in the archives :: ')
            pattern = re.compile(r"^\w{16,}$")
            if not pattern.match(username):
                print('[-] The ancient scribes only accept proper names-no forbidden symbols allowed.')
                continue
            encrypted_creds = encrypt_creds(username)
            print(f'[+] Thy credentials have been sealed in the encrypted scrolls: {encrypted_creds.hex()}')
        elif ch == '2':
            pwd = input('[+] Whisper the sacred incantation to enter the Forbidden Sanctum :: ')
            if admin_login(pwd):
                print(f"[+] The gates open before you, Keeper of Secrets! {open('flag.txt').read()}")
                exit()
            else:
                print('[-] You salt not pass!')
        elif ch == '3':
            print('[+] Thou turnest away from the shadows and fade into the mist...')
            exit()
        else:
            print('[-] The oracle does not understand thy words.')

if __name__ == '__main__':
    main()
```

### Solution:
Ở bài này, mục đích của ta là phải recover lại `password` được tạo bởi 20 kí tự là chữ cái hoặc chữ số.
Vì bài này là `AES-CBC`, ta cùng xem lại quá trình `decrypt` của `AES-CBC`:

![image](https://hackmd.io/_uploads/B1Qf1yJpJe.png)

Vì ta được quyền tùy chỉnh tiền tố của `ciphertext` nên thuật toán của ta sẽ là bruteforce từng kí tự của `plaintext`. Xem xét ví dụ cho dễ hiểu:
- Nếu như ta gửi `user = b"000000000000000" (15 kí tự 0)` thì khi gửi lên server `padded = user + flag` tức là kí tự cuối cùng của block đầu tiên là kí tự đầu tiên của `flag`.
- Đến đây thì ta sẽ bruteforce lần lượt từng kí tự của `flag` rồi check block tương ứng của `new_plaintext` với `plaintext` ở trên.

Code:
```python
from pwn import *
from tqdm import tqdm
from Crypto.Util.Padding import pad

alphabet = string.ascii_letters+string.digits

io = remote("94.237.54.190", 40497, level = 'debug')

password = ""
length = 32 + 15
for _ in tqdm(range(20)):
    user = "0" * length

    io.sendafter(b"Choose your path, traveler :: ", b"1\n")
    io.sendafter(b'[+] Speak thy name, so it may be sealed in the archives :: ', user.encode() + b'\n')

    io.recvuntil(b"[+] Thy credentials have been sealed in the encrypted scrolls: ")
    target = io.recvline().decode()
    target = bytes.fromhex(target)

    for ch in alphabet:
        cur_user = user + password + ch
        io.sendafter(b"Choose your path, traveler :: ", b"1\n")
        io.sendafter(b'[+] Speak thy name, so it may be sealed in the archives :: ', cur_user.encode() + b'\n')

        io.recvuntil(b"[+] Thy credentials have been sealed in the encrypted scrolls: ")
        cur = io.recvline().decode()
        cur = bytes.fromhex(cur)

        if cur[16:48] == target[16:48]:
            password += ch
            print(password)
            length -= 1
            break



io.sendafter(b"Choose your path, traveler :: ", b"2\n")
io.sendafter(b"[+] Whisper the sacred incantation to enter the Forbidden Sanctum :: ", password.encode() + b'\n')
io.recvall()

# Flag: HTB{encrypting_with_CBC_decryption_is_as_insecure_as_ECB___they_also_both_fail_the_penguin_test_cf4d671608cad423ca312ad501b030b8}
```

## 5. Twin Oracle (hard)
### Challenge:
Source code:
```python
from Crypto.Util.number import *

FLAG = bytes_to_long(open('flag.txt', 'rb').read())

MENU = '''
The Seers await your command:

1. Request Knowledge from the Elders
2. Consult the Seers of the Obsidian Tower
3. Depart from the Sanctum
'''
class ChaosRelic:
    def __init__(self):
        self.p = getPrime(8)
        self.q = getPrime(8)
        self.M = self.p * self.q
        self.x0 = getPrime(15)
        self.x = self.x0
        print(f"The Ancient Chaos Relic fuels the Seers' wisdom. Behold its power: M = {self.M}")

    def next_state(self):
        self.x = pow(self.x, 2, self.M)

    def get_bit(self):
        self.next_state()
        return self.extract_bit_from_state()

    def extract_bit_from_state(self):
        return self.x % 2

class ObsidianSeers:
    def __init__(self, relic):
        self.relic = relic
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.n = self.p * self.q
        self.e = 65537
        self.phi = (self.p - 1) * (self.q - 1)
        self.d = pow(self.e, -1, self.phi)


    def sacred_encryption(self, m):
        return pow(m, self.e, self.n)

    def sacred_decryption(self, c):
        return pow(c, self.d, self.n)

    def HighSeerVision(self, c):
        return int(self.sacred_decryption(c) > self.n//2)

    def FateSeerWhisper(self, c):
        return self.sacred_decryption(c) % 2

    def divine_prophecy(self, a_bit, c):
        return self.FateSeerWhisper(c) if a_bit == 0 else self.HighSeerVision(c)

    def consult_seers(self, c):
        next_bit = self.relic.get_bit()
        response = self.divine_prophecy(next_bit, c)
        return response



def main():
    print("You stand before the Seers of the Obsidian Tower. They alone hold the knowledge you seek.")
    print("But be warned—no force in Eldoria can break their will, and their wisdom is safeguarded by the power of the Chaos Relic.")
    my_relic = ChaosRelic()
    my_seers = ObsidianSeers(my_relic)
    counter = 0

    while counter <= 1500:
        print(MENU)
        print(my_relic.result())
        option = input('> ')

        if option == '1':
            print(f"The Elders grant you insight: n = {my_seers.n}")
            print(f"The ancient script has been sealed: {my_seers.sacred_encryption(FLAG)}")
        elif option == '2':
            ciphertext = int(input("Submit your encrypted scripture for the Seers' judgement: "), 16)
            print(f'The Seers whisper their answer: {my_seers.consult_seers(ciphertext)}')
        elif option == '3':
            print("The doors of the Sanctum close behind you. The Seers watch in silence as you depart.")
            break
        else:
            print("The Seers do not acknowledge your request.")
            continue

        counter += 1

    print("The stars fade, and the Seers retreat into silence. They shall speak no more tonight.")

if __name__ == '__main__':
    main()
```

### Solution:
Nếu như ta gửi `m = n - 1 => c = m^e = (n-1)^e (mod n)`:
- Vì `n` lẻ nên `n - 1` chẵn => `FateSeerWhisper(c)` sẽ trả về `0`.
- Vì `m = n - 1 => m > n // 2` => `HighSeerVision(c)` sẽ trả về `1`.

Từ đây, ta lấy khoảng 15 giá trị đầu tiên của `oracle`, và tất nhiên, những bit `1` sẽ là thời điểm mà `oracle` trả về hàm `FateSeerWhisper(c)` và bit `0` là thời điểm mà `oracle` trả về hàm `HighSeerVision(c)`. Tới đây, ta sẽ bruteforce các giá trị `x_0` rồi kiểm tra dãy 15 bit đầu mà `x_0` sinh ra có khớp với dãy bit mà ta vừa lấy được từ `oracle` hay không, nếu khớp thì ta đã tìm được `x_0` của bài. Từ đó, sinh ra các bit tiếp theo.

Vậy, ta đã biết được thời điểm hiện tại, server sẽ trả về hàm `HighSeerVision(c) (1)` hay là `FateSeerWisper(c) (0)`

Nhiệm vụ của ta bây giờ là lợi dụng thông tin mà server trả về để tìm giá trị `m` chính xác.

Cùng phân tích 1 chút về 2 hàm `oracle` mà server trả về:
- `FateSeerWisper(c)`: nếu ta gửi `c' = (m * 2)^e = m^e * 2^e = c * 2^e (mod n)` thì khi server giải mã `c'` kết quả sẽ là `2m`.
    - Nếu như server trả về `1` tức là `2m % n = 1` => `2m > n` <=> `m > n/2` (bởi vì `n` lẻ, `2m` chẵn và `m < n`).
    - Nếu server trả về `0` <=> `2m % n = 0` <=> `2m < n` <=> `m < n/2`.
- `HighSeerVision(c)`: hàm này trả về `1` nếu `m > n/2` và trả về `0` nếu `m < n/2`.

Quan sát kĩ một chút, ta sẽ thấy rằng nếu như server trả về `1` khi ta gửi `FateSeerWisper(c * 2^e % n) và HighSeerVision(c % n)` thì điều kiện ta nhận được đều là `m > n/2` và ngược lại nếu server trả về `0` thì điều kiện đều là `m < n/2`.
Từ đây, ta nhận thấy được mối quan hệ của 2 hàm `oracle` này.

Xem [bài viết này](https://github.com/ashutosh1206/Crypton/blob/master/RSA-encryption/Attack-LSBit-Oracle/README.md) để hiểu rõ hơn về thuật toán.

Nếu chỉ sử dụng kết quả của oracle `FateSeerWisper(c) (LSBit)` thì ta cần khoảng 1024 lần hỏi, nhưng như vậy thì sẽ bị thiếu vì server chỉ cho ta max 1500 lần hỏi => số lượng kết quả của 2 hàm oracle xấp xỉ 1 nửa ~700 800.

Vậy, nếu chỉ sử dụng `FateSeerWisper(c)` thì ta sẽ không thể tìm được chính xác giá trị `m`, tương tự nếu chỉ dùng `HighSeerVision(c)` cũng vậy. Nhưng vì 2 hàm đó có mối tương đồng với nhau nên ta có thể hợp 2 hàm oracle đó lại để sử dụng cả 2 luôn.

Code:
```python
from pwn import *
from tqdm import tqdm
from Crypto.Util.number import *
from sage.all import *

io = remote("94.237.51.14", 55839)
# io = process(["python3", "/home/team/CodePy/Cyber Apocalypse CTF 2025: Tales from Eldoria/Twin Oracles/server.py"])

FLAG = io.recvline().decode()

io.recvuntil(b"M = ")
M = int(io.recvline().strip().decode())

io.sendafter(b"> ", b"1\n")
io.recvuntil(b"n = ")
n = int(io.recvline().strip().decode())
io.recvuntil(b"The ancient script has been sealed: ")
c = int(io.recvline().strip().decode())
e = 65537

def oracle(num):
    io.sendafter(b"> ", b"2\n")
    io.sendafter(b"Submit your encrypted scripture for the Seers' judgement: ", hex(num).encode() + b'\n')
    io.recvuntil(b"The Seers whisper their answer: ")
    return io.recvline().strip().decode()


#  Find x0
number_question_for_x0 = 15
bits = ""
for i in tqdm(range(number_question_for_x0)):
    ok = oracle(pow(n - 1, e, n))
    bits += ok

X0 = 0
for x0 in range((1 << 14), (1 << 15)):
    if not isPrime(x0):
        continue

    x, ok = x0, True
    for i in range(number_question_for_x0):
        x = pow(x, 2, M)
        if int(x % 2) != int(bits[i]):
            ok = False
            break
    if ok:
        X0 = x0
        break


bits, x0 = "", X0
for i in range(1500):
    x0 = pow(x0, 2, M)
    bits += str(x0 % 2)
bits = bits[number_question_for_x0:]



# Find flag
high = ZZ(n)
low = ZZ(0)
i0, i1 = 0, 1
for j in tqdm(range(len(bits))):
    bit = bits[j]

    if bit == '1':
        output = oracle(c * pow(2**i0, e, n) % n)
    else:
        output = oracle(c * pow(2**i1, e, n) % n)

    if output == "0":
        high = (low + high) / 2
    else:
        low = (low + high) / 2

    i0 += 1
    i1 += 1

high = int(high)
print(high)
print(long_to_bytes(high))


# Flag: HTB{1_l0v3_us1ng_RS4_0r4cl3s___3v3n_4_s1ngl3_b1t_1s_3n0ugh_t0_g3t_m3_t0_3ld0r14!_6233599df7b453a9a1080c73e1b9f12b}
```