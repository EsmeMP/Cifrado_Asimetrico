# este algoritmo permite que cada parte genere su clave privada y su clave publica,
# solo se intercambian sus claves publicas y mantienen sus claves privadas

# importaciones (genera parametros y claves diffierHellman/convierte palabras a bytes/deriva una clave simetrica )
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import binascii

# genera parametros, generador(2 o 5, bits usados)
def generar_parametros():
    parametros = dh.generate_parameters(generator=2, key_size=2048)
    return parametros

# genera claves privadas y publicas (a partir de la clave privada se calcula la clave publica)
def generar_claves(parametros):
    private_key = parametros.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# las claves deben ser correspondientes, aun no es apta para cifrar correctamente, se pasa por kdf 
def calcular_llave_compartida(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    # Derivar una clave simétrica de 32 bytes
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_key)
    return derived_key

# función auxiliar: serializa clave pública a formato PEM (para intercambio)
def serializar_publica(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# función auxiliar: carga clave pública desde formato PEM
def cargar_publica(pem_bytes):
    return load_pem_public_key(pem_bytes)

# simulación de dos participantes (A y B)
def demo_intercambio():
    # ambos usan los mismos parámetros
    parametros = generar_parametros()

    # participante A genera sus claves
    priv_a, pub_a = generar_claves(parametros)
    pem_pub_a = serializar_publica(pub_a)

    # participante B genera sus claves
    priv_b, pub_b = generar_claves(parametros)
    pem_pub_b = serializar_publica(pub_b)

    # intercambio de claves públicas
    pub_a_loaded = cargar_publica(pem_pub_a)
    pub_b_loaded = cargar_publica(pem_pub_b)

    # ambos calculan la misma clave compartida
    key_a = calcular_llave_compartida(priv_a, pub_b_loaded)
    key_b = calcular_llave_compartida(priv_b, pub_a_loaded)

    assert key_a == key_b, "Error: las claves derivadas no coinciden"

    # convertir a hexadecimal solo para mostrar (en práctica, no se imprime)
    clave_hex = binascii.hexlify(key_a).decode()
    return pem_pub_a, pem_pub_b, clave_hex

def main():
    print("=== Diffie-Hellman ===")
    print("Este algoritmo permite que dos partes generen una clave compartida sin intercambiar la clave privada.\n")

    # ejecuta la simulación de intercambio
    pem_a, pem_b, clave_hex = demo_intercambio()

    print("Claves generadas. Intercambia la clave pública con tu par para derivar la clave compartida.\n")
    print("Clave pública A (bytes):")
    print(pem_a.decode())
    print("Clave pública B (bytes):")
    print(pem_b.decode())
    print("Clave simétrica derivada (hex):", clave_hex)

if __name__ == "__main__":
    main()
