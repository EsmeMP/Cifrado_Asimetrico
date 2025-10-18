# Este algoritmo usa criptografía de curva elíptica (ECC) para generar claves privadas y públicas.
# A diferencia de RSA, ECC no cifra directamente; se usa para derivar una clave simétrica compartida
# mediante ECDH (Elliptic Curve Diffie-Hellman), que luego puede emplearse con AES-GCM para cifrar mensajes.

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, base64

# Genera las claves ECC (privada y pública) usando la curva SECP256R1
def generar_claves():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Guarda las claves en archivos PEM
def guardar_claves(private_key, public_key):
    with open("private_ecc.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_ecc.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Claves ECC guardadas correctamente.")

# Carga las claves desde archivos PEM
def cargar_claves():
    with open("private_ecc.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("public_ecc.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

# Cifrado con ECC (ECDH + AES-GCM)
def cifrar(mensaje: bytes, public_key):
    # Genera una clave efímera para el remitente
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)
    
    # Deriva una clave simétrica de 32 bytes con HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecdh handshake'
    ).derive(shared_key)
    
    # Cifra el mensaje con AES-GCM usando la clave derivada
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv)
    ).encryptor()
    ciphertext = encryptor.update(mensaje) + encryptor.finalize()
    
    # Empaqueta datos necesarios para descifrar
    encrypted_data = {
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
        "ephemeral_public": base64.b64encode(
            ephemeral_private.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()
    }
    return encrypted_data

# Descifrado con ECC
def descifrar(private_key, encrypted_data):
    # Recupera la clave pública efímera del remitente
    ephemeral_public = serialization.load_pem_public_key(
        base64.b64decode(encrypted_data["ephemeral_public"])
    )
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public)
    
    # Deriva la misma clave simétrica
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecdh handshake'
    ).derive(shared_key)
    
    # Descifra con AES-GCM
    iv = base64.b64decode(encrypted_data["iv"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])
    
    decryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv, tag)
    ).decryptor()
    mensaje = decryptor.update(ciphertext) + decryptor.finalize()
    return mensaje

def main():
    print("=== ECC ===")
    print("1) Generar claves")
    print("2) Cifrar mensaje")
    print("3) Descifrar mensaje")
    opcion = input("Elige una opción: ")

    if opcion == "1":
        private_key, public_key = generar_claves()
        guardar_claves(private_key, public_key)
    elif opcion == "2":
        _, public_key = cargar_claves()
        texto = input("Mensaje a cifrar: ").encode()
        cifrado = cifrar(texto, public_key)
        print("Mensaje cifrado (JSON):")
        print(cifrado)
    elif opcion == "3":
        private_key, _ = cargar_claves()
        print("Pega el JSON cifrado:")
        import json
        encrypted_data = json.loads(input())
        try:
            mensaje = descifrar(private_key, encrypted_data)
            print("Mensaje descifrado:", mensaje.decode())
        except Exception as e:
            print("Error al descifrar:", e)
    else:
        print("Opción no válida")

if __name__ == "__main__":
    main()
