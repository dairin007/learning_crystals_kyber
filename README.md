# crystals kyber

https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

- NIST の PQC のコンペで採択された耐量子計算機暗号の KEM

- 耐量子計算機暗号のコンペは暗号のプリミティブ，つまり原理を募集してそのプリミティブをもとに公開鍵などを構築することを目的としている

- crystals kyber は IND-CPA 安全な KEM を構成してからこれをもとに IND-CCA 安全な KEM を構成して，これをもとに PKI を構成する

# params

|           | n   | k   | q    | η1  | η2  | (du,dv) | δ        |
| --------- | --- | --- | ---- | --- | --- | ------- | -------- |
| Kyber512  | 256 | 2   | 3329 | 3   | 2   | (10, 4) | 2^{−139} |
| Kyber768  | 256 | 3   | 3329 | 2   | 2   | (10, 4) | 2^{−164} |
| Kyber1024 | 256 | 4   | 3329 | 2   | 2   | (11, 5) | 2^{−174} |

# アルゴリズムで使用している関数で使用しているプリミティブ

## デフォルトの

- XOF is SHAKE-128
- H is SHA3-256
- G is SHA3-512
- PRF(s,b) is SHAKE-256(s||b)
- KDF is SHAKE-256

## 90s と名づけられた aes と sha2 を使った場合のプリミティブ

- XOF(p,i,j) is AES-256-CTR(initialized zero), p is key, i||j is 12bit zero padding nonce
- H is SHA-256
- G is SHA-512
- PRF(s,b) is AES-256-CTR(initialized zero), s is key, b is 12bit zero padding nonce
- KDF is SHA-256
