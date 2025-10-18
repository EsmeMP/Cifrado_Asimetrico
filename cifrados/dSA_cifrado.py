from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

def generar_claves():
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def firmar(private_key, mensaje: bytes):
    signature = private_key.sign(
        mensaje,
        hashes.SHA256()
    )
    return signature

def verificar(public_key, mensaje: bytes, signature: bytes):
    try:
        public_key.verify(signature, mensaje, hashes.SHA256())
        return True
    except:
        return False

def main():
    print("=== DSA (Firma Digital) ===")
    opcion = input("Elige: 1) Firmar  2) Verificar firma: ")
    if opcion == "1":
        texto = input("Mensaje a firmar: ").encode()
        private_key, public_key = generar_claves()
        signature = firmar(private_key, texto)
        print("Firma generada:", signature)
        print("Guarda la clave privada para verificar más tarde")
    elif opcion == "2":
        print("Verificar requiere mensaje, firma y clave pública previamente guardada")
    else:
        print("Opción no válida")

if __name__ == "__main__":
    main()
