# Este algoritmo usa DSA (Digital Signature Algorithm) para crear y verificar firmas digitales.
# Sirve para autenticar mensajes y garantizar su integridad, NO para cifrar o descifrar datos.
# Cada firma se genera con una clave privada y se verifica con la clave pública correspondiente.

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
import base64, json

# Genera un par de claves DSA (privada y pública)
def generar_claves():
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Guarda las claves en archivos PEM (para reutilizarlas luego)
def guardar_claves(private_key, public_key):
    with open("private_dsa.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_dsa.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print("Claves DSA guardadas correctamente.")

# Carga las claves desde archivos PEM
def cargar_claves():
    with open("private_dsa.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("public_dsa.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

# Firma digitalmente un mensaje con la clave privada
def firmar(private_key, mensaje: bytes):
    signature = private_key.sign(
        mensaje,
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()  # Firma codificada en base64

# Verifica una firma con la clave pública
def verificar(public_key, mensaje: bytes, signature_b64: str):
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, mensaje, hashes.SHA256())
        return True
    except Exception as e:
        print("Error en verificación:", e)
        return False

def main():
    print("=== DSA (Firma Digital) ===")
    print("1) Generar claves")
    print("2) Firmar mensaje")
    print("3) Verificar firma")
    opcion = input("Elige una opción: ")

    if opcion == "1":
        private_key, public_key = generar_claves()
        guardar_claves(private_key, public_key)

    elif opcion == "2":
        private_key, public_key = cargar_claves()
        mensaje = input("Mensaje a firmar: ").encode()
        firma = firmar(private_key, mensaje)
        print("\nFirma generada (Base64):")
        print(firma)
        print("\nGuarda también este JSON para verificar después:")
        datos = {"mensaje": mensaje.decode(), "firma": firma}
        print(json.dumps(datos, indent=4))

    elif opcion == "3":
        _, public_key = cargar_claves()
        print("Pega el JSON con el mensaje y la firma:")
        try:
            datos = json.loads(input())
            mensaje = datos["mensaje"].encode()
            firma = datos["firma"]
            if verificar(public_key, mensaje, firma):
                print("✅ Firma válida. El mensaje es auténtico.")
            else:
                print("❌ Firma inválida o mensaje alterado.")
        except Exception as e:
            print("Error al verificar:", e)

    else:
        print("Opción no válida")

if __name__ == "__main__":
    main()
