import os
import importlib

def main():
    # Název modulu uložený v proměnné
    prom = "pyspx.shake_128s"
    
    # Importovat modul na základě názvu v proměnné
    algorithm_module = importlib.import_module(prom)

    if algorithm_module:
        # Generování náhodného klíče
        seed = os.urandom(48)
        # Podepisování zprávy
        message = "hello"
        message = message.encode()
        public_key, secret_key = algorithm_module.generate_keypair(seed)
        signature = algorithm_module.sign(message, secret_key)
        
        # Ověření zprávy
        message = "hello8"
        message = message.encode()
        print(algorithm_module.verify(message, signature, public_key))

if __name__ == "__main__":
    main()

