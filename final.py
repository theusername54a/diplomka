import pyspx.shake_128s
import random
import string

import os

seed = os.urandom(48)


message ="hello"
message = message.encode()
public_key, secret_key = pyspx.shake_128s.generate_keypair(seed)
signature = pyspx.shake_128s.sign(message, secret_key)
message ="hello"
message = message.encode()
print(pyspx.shake_128s.verify(message, signature, public_key))
