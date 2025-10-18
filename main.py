from cifrados import rSA_cifrado, dSA_cifrado, eCC_cifrado, diffie_Hellman_cifrado

print("\n=== Cifrado Asimétrico ===")
print("1. RSA")
print("2. ECC (Elliptic Curve Cryptography)")
print("3. DSA / ECDSA")
print("4. Diffie-Hellman")
opcion = input("Elige cifrado: ")
if opcion == "1":
    rSA_cifrado.main()
elif opcion == "2":
    dSA_cifrado.main()
elif opcion == "3":
    eCC_cifrado.main()
elif opcion == "4":
    diffie_Hellman_cifrado.main()
