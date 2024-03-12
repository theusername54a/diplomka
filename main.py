import falcon.falcon
sk = falcon.SecretKey(512)
pk = falcon.PublicKey(sk)

sig = sk.sign(b"Hello")

print(pk.verify(b"Hello", sig))
