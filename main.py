# IMPORTACIONES (rutas de los otros scripts)
from cifrados import diffie_Hellman_cifrado, dSA_cifrado, eCC_cifrado, rSA_cifrado 
import os

def menu():
    print("=== Cifrado Asimétrico ===")
    print("1. RSA")
    print("2. DSA")
    print("3. ECC")
    print("4. Diffie–Hellman")
    opcion = input("Elige una opción: ")

    if opcion == "1":
        os.system("python cifrados/RSA_cifrado.py")
    elif opcion == "2":
        os.system("python cifrados/DSA_cifrado.py")
    elif opcion == "3":
        os.system("python cifrados/ECC_cifrado.py")
    elif opcion == "4":
        os.system("python cifrados/Diffie–Hellman_cifrado.py")
    else:
        print("Opción no válida.")

if __name__ == "__main__":
    menu()
