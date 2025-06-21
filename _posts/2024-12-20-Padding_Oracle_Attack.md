---
title: 'Padding Oracle Attack'
date: 2024-12-20 00:00:00 +0700
categories: [ctf]
tags: [Crypto]
published: true
description: "Introduce to Padding Oracle Attack"
---

Padding Oracle là một loại lỗ hổng trong các giao thức hoặc hệ thống block cipher khi sử dụng chế độ hoạt động có padding (ví dụ: AES-CBC). Lỗ hổng này cho phép các attacker tận dụng thông tin được tiết lộ về việc padding trong ciphertext (hoặc plaintext) có hợp lệ hay không để giải mã hoặc giả mạo dữ liệu mã hóa mà không cần khóa bí mật.

Ví dụ về tiết lộ thông tin padding:
```python
def check_padding(self, ct):
    ct = bytes.fromhex(ct)
    iv, ct = ct[:16], ct[16:]
    cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
    pt = cipher.decrypt(ct)  # does not remove padding
    try:
        unpad(pt, 16)
    except ValueError:
        good = False
    else:
        good = True
    return {"result": good}
```

## Khái niệm
### Padding là gì?
- Padding trong mã hóa được sử dụng để đảm bảo rằng dữ liệu đầu vào của một thuật toán mã hóa khối có kích thước bội số của độ dài khối (block size).
- Một kiểu padding phổ biến là **PKCS#7**, trong đó các bytes được thêm vào cuối plaintext để đạt đủ độ dài khối. Giá trị của padding bằng số bytes cần được thêm vào.
Ví dụ với block size = 16 bytes:
- Nếu plaintext là 10 byte: `b'aaaaaaaaaa'` thì 6 bytes padding được thêm vào là `b'aaaaaaaaaa\x06\x06\x06\x06\x06\x06`
- Nếu plaintext đã đủ 16 bytes: `b'abcdefghiklmnopq` thì 1 khối mới gồm 16 bytes sẽ được thêm vào `b'abcdefghiklmnopq\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10`

### Oracle là gì?
- "Oracle" là một phản hồi có ích cho attacker
- Trong Padding Oracle, hệ thống sẽ kiểm tra tính hợp lệ của padding trong ciphertext được giải mã. Hệ thống sẽ:
    - Trả về phản hồi chỉ ra rằng padding là hợp lệ
    - Hoặc trả về lỗi nếu padding không hợp lệ

### Attacker có thể khai thác gì?
- Attacker sử dụng hệ thống như một "oracle" để gửi các ciphertext giả mạo và quan sát phản hồi (hợp lệ hoặc không).
- Bằng cách thay đổi các bytes trong ciphertext và phân tích phản hồi từ hệ thống, attacker có thể:
    - Giải mã ciphertext: tìm plaintext mà không cần biết key.
    - Giả mạo ciphertext: tạo ra ciphertext mới hợp lệ.

## AES-CBC

Ta nhắc lại về AES-CBC (Cipher Block Chaining): plaintext được chia thành các block 16 bytes (`P1`, `P2`, ...) và mỗi block được XOR với ciphertext của block trước đó (hoặc `IV` cho block đầu tiên) trước khi mã hóa.

Công thức giải mã:

$$
P_i = C_{i-1} \oplus D_k(C_i)
$$

Trong đó:
- $P_i$: plaintext của block thứ $i$.
- $C_i$: ciphertext của block thứ $i$.
- $D_k(C_i)$: kết quả giải mã của block $C_i$ với khóa $k$.

## Padding Attack
Ta xem xét trong trường hợp attack 1 block.

![image](https://hackmd.io/_uploads/ByxFXQHOyl.png)

Dễ thấy, để recover lại `P2` thì ta phải biết được `I2`.
Vậy, làm sao để tìm được `I2`?

Như ta đã biết, Oracle trả về `True` khi các padding ở cuối của `P2` thỏa mãn `n` bytes cuối có giá trị `n`. Bây giờ ta muốn tìm byte cuối cùng của `P2`.

![image](https://hackmd.io/_uploads/ByplIXS_Jx.png)

Ta sẽ brute force 255 giá trị của $t_i$ (byte cuối cùng của $C_1$) đến khi nào Oracle hợp lệ (tức là byte cuối của $P_2$ là `\x01`). Từ đó, ta tính được $x_i = t_i \oplus 01$. Sau khi tìm được $x_i$, ta chỉ cần lấy byte cuối cùng của $C_1$ (chính thức) XOR với $x_i$ là ra được byte chính thức cuối cùng của $P_2$.

Khi tìm được byte cuối cùng rồi, thì ta tiếp tục recover từ cuối về, thay vì padding là `\x01` thì bây giờ sẽ là `\x02\x02`, `\x03\x03\x03`, ...

Code:
```python
BLOCK_SIZE = 16

def attack_block(iv, ciphertext):
    after_decrypt = b""

    for i in reversed(range(16)):
        padding = bytes([16 - i] * (16 - i))
        for ch in range(256):
            _iv = bytes(i) + xor(padding, bytes([ch]) + after_decrypt)

            if oracle(_iv, ciphertext):
                after_decrypt = bytes([ch]) + after_decrypt
                break

    return xor(iv, after_decrypt)

def full_attack(iv, ciphertext):
    plaintext = b""

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        plaintext += attack_block(iv, ciphertext[i:i+BLOCK_SIZE])
        iv = ciphertext[i:i+BLOCK_SIZE]

    return plaintext
```


Tham khảo thêm:

https://www.youtube.com/watch?v=4EgD4PEatA8&t=693s&ab_channel=BrianYen
https://www.nccgroup.com/us/research-blog/cryptopals-exploiting-cbc-padding-oracles/