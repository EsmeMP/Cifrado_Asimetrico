# si la clave privada ya existe, se reutiliza para descifrar
# IMPORTACIONES (rsa genera las claves asimetricas, padding -> relleno cripografico, algoritmo hash)
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os

# Genera las claves y las guarda en archivos PEM(guarda informacion criptografica)
def generar_y_guardar_claves():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Guarda clave privada
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Guarda clave publica
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Claves RSA generadas y guardadas correctamente.")
    return private_key, public_key


# Carga las claves existentes si ya fueron generadas
def cargar_claves():
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key


# Cifrar mensaje con la clave pública
def cifrar(mensaje: bytes, public_key):
    mensaje_cifrado = public_key.encrypt(
        mensaje,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(mensaje_cifrado)  # para que se pueda imprimir fácilmente


# Descifrar mensaje con la clave privada
def descifrar(mensaje_cifrado_b64: bytes, private_key):
    mensaje_cifrado = base64.b64decode(mensaje_cifrado_b64)
    mensaje_descifrado = private_key.decrypt(
        mensaje_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensaje_descifrado


def main():
    print("=== RSA ===")
    opcion = input("Elige: 1) Cifrar  2) Descifrar: ")

    # Verifica si existen las claves
    if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
        private_key, public_key = cargar_claves()
    else:
        private_key, public_key = generar_y_guardar_claves()

    if opcion == "1":
        texto = input("Mensaje a cifrar: ").encode()
        cifrado = cifrar(texto, public_key)
        print("Mensaje cifrado (base64):", cifrado.decode())
    elif opcion == "2":
        cifrado_b64 = input("Pega el mensaje cifrado (base64): ").encode()
        try:
            descifrado = descifrar(cifrado_b64, private_key)
            print("Mensaje descifrado:", descifrado.decode())
        except Exception as e:
            print("Error al descifrar:", e)
    else:
        print("Opción no válida")


if __name__ == "__main__":
    main()






