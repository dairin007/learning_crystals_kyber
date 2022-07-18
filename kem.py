# crystal kyber 512 by https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

# params
#            n  k  q   η1 η2 (du, dv)   δ
# Kyber512  256 2 3329 3  2  (10, 4)  2^−139
# Kyber768  256 3 3329 2  2  (10, 4)  2^−164
# Kyber1024 256 4 3329 2  2  (11, 5)  2^−174

# Instance(default)
# XOF is SHAKE-128
# H is SHA3-256
# G is SHA3-512
# PRF(s,b) is SHAKE-256(s||b)
# KDF is SHAKE-256

# Instance(90s)
# XOF(p,i,j) is AES-256-CTR(initialized zero), p is key, i||j is 12bit zero padding nonce
# H is SHA-256
# G is SHA-512
# PRF(s,b) is AES-256-CTR(initialized zero), s is key, b is 12bit zero padding nonce
# KDF is SHA-256

import hashlib as hash
import secrets as sec
import math

# param setting
param_k:int=2
param_n:int=256
param_q:int=3329

def Parse(in_stream:bytes, buf1:int, length:int):
  i=0
  j=0
  r=[0]*384
  while(j<length and i+3<buf1):
    d1=in_stream[i] | (in_stream[i+1]<<8) & 0xfff
    d2=math.ceil(in_stream[i+1]>>4) | (in_stream[i+2] <<4) & 0xfff
    if d1<param_q:
      r[j]=d1
      j+=1
    if d2<length and j<param_q:
      r[j]=d2
      j+=1
    i+=3
  result = [0]*2
  result[0]=r
  result[1]=j
  return result



def GenMatrixA(pseed:bytes):
  # matrixA is param_k*param_k matrix
  # element is poly
  ctr=0
  matrixA=[[0]*param_k for _ in range(param_k)]
  for i in range(0, param_k):
    for j in range(0, param_k):
      shake128_1=hash.shake_128()
      shake128_1.update(pseed+bytes(j)+bytes(i))
      output_len=504
      output=shake128_1.digest(672)
      res_parse=Parse(bytes(output[0:output_len]), output_len, param_n)
      matrixA[i][j]=res_parse[0]
      ctr=res_parse[1]
      # 多項式の係数が256個になるまで埋める
      while(ctr<param_n):
        res_2=Parse(bytes(output[504:672]), 168, param_n-ctr)
        missing=res_2[0]
        ctr_tmp=res_2[1]
        for k in range(ctr, param_n):
          matrixA[i][j][k]=missing[k-ctr]
        ctr+=ctr_tmp
  return matrixA

def CBD(i:int):
  pass

def PRF():
  prf=hash.shake_256()

def MakeCPAKey512():
  # sk len =768
  # pk len =800

  # d <- B^32
  seed_d = sec.token_bytes(32)
  # (ρ, σ) <- G(d)
  sh3_1 = hash.sha3_512()
  sh3_1.update(seed_d)
  union_seed=sh3_1.digest()
  pseed=union_seed[:32]
  nseed=union_seed[32:]
  nonce=0
  assert len(pseed)==32 and len(nseed)==32
  # make A matrix for NTT domain
  GenMatrixA(pseed)
  # make sk
  sk=[[0]*param_k for _ in range(param_k)]
  for i in range(0, param_k):
      sk[i]=CBD(PRF(nseed, nonce))


  # return cpaPublicKey, cpaSecretKey

# make key
def MakeKey512():
  MakeCPAKey512()
  pass

MakeCPAKey512()
