from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# 1. Generar clave privada
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# 2. Generar clave pública a partir de la privada
public_key = private_key.public_key()

# 3. Mensaje a cifrar
mensaje = b"Hola mundo, este es un mensaje secreto"

# 4. Cifrar con la clave pública
mensaje_cifrado = public_key.encrypt(
    mensaje,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Mensaje cifrado:", mensaje_cifrado)

# 5. Descifrar con la clave privada
mensaje_descifrado = private_key.decrypt(
    mensaje_cifrado,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Mensaje descifrado:", mensaje_descifrado.decode())
