from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

def generar_claves():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def main():
    print("=== ECC ===")
    opcion = input("Elige: 1) Generar claves: ")
    if opcion == "1":
        private_key, public_key = generar_claves()
        print("Claves generadas con ECC.")
        # Puedes guardar private_key y public_key con .private_bytes() y .public_bytes()
    else:
        print("Opción no válida")

if __name__ == "__main__":
    main()
