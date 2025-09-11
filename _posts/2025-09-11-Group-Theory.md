---
title: 'Group Theory'
date: 2025-09-11 00:00:00 +0700
categories: [Cryptography]
tags: [Group Theory]
published: true
description: "Some theorems and lemmas of Group Theory"
---

# Nhóm (Groups)
Một **nhóm** là một tập hợp $G$ cùng với một phép toán nhị phân $\cdot$ sao cho:
1. Với mọi $x, y \in G$, ta có $x \cdot y \in G$ (tính **đóng** **closure**).
2. Tồn tại một **phần tử đơn vị** $1 \in G$ sao cho $x \cdot 1 = 1 \cdot x = x$ với mọi $x \in G$ (phần tử đơn vị **identity**).
3. Với mọi $x, y, z \in G$, ta có $(xy)z = x(yz)$ (tính **kết hợp associativity**).
4. Với mọi $x \in G$, tồn tại một phần tử nghịch đảo $x^{-1} \in G$ sao cho $xx^{-1} = x^{-1}x = 1$ (tính **nghịch đảo inverse**).

Nếu ta chỉ có tính đóng và kết hợp, thì $G$ được gọi là **bán nhóm (semigroup)**.

Nếu có thêm phần tử đon vị, thì $G$ được gọi là **nửa nhóm (monoid)**.

Nếu $xy=yx$ với một số $x,y \in G$, ta nói $x,y$ **giao hoán (commutative)**. Nếu điều này đúng với mọi $x,y \in G$, ta nói $G$ là một **nhóm Abel** (hay **nhóm giao hoán**).

Một **đồng cấu nhóm (Homomorphism)** giữa hai nhóm $G,H$ là một ánh xạ $f : G \rightarrow H$  thỏa mãn $f(x)f(y) = f(xy) \ \ \ \ \ \forall x,y \in G$. Nếu $f$ là **song ánh** thì ta gọi nó là một **đẳng cấu (isomorphism)**.

**Bậc** hay **Cấp (order)** của một phần tử $g \in G$ là số nguyên dương $k$ nhỏ nhất sao cho $g^k=1$. Điều này phải tồn tại trong một **nhóm hữu hạn (finite group)**.

**Theorem:** Nếu $x \in G$ có bậc là $h$, thì $x^m = 1$ khi và chỉ khi $h \mid m$.

**Theorem:** Nếu $x \in G$ có bậc là $mn$ với $m,n$ **nguyên tố cùng nhau**, thì $x$ có thể được viết dưới dạng $x=uv$ trong đó $u$ có bậc là $m$ và $v$ có bậc $n$.

Ta viết $H \le G$ để biểu diễn rằng $H$ là một **subgroup** của $G$. Trong trường hợp $H \ne G$ thì ta viết $H < G$.

**Theorem:** Một tập con khác rỗng $H \subseteq G$ là một **subgroup** khi và chỉ khi $H$ đóng dưới phép nhân.

**Theorem:** Một tạp con khác rỗng $H \subset G$ là một **subgroup** khi và chỉ khi $H^2 \subset H$.

**Lemma:** Với một **subgroup** $H$, với mọi $h \in H$ ta có $hH = H = Hh$.

**Corollary:** Với mọi tập $S \subset H$ ta có $SH = H = HS$.

**Theorem:** Cho $g \in G$ và $H \le G$. Khi đó $g^{-1}Hg$ là một **subgroup** của $G$ và **đẳng cấu (isomorphic)** với $H$.

