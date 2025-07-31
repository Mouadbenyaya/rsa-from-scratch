import random


def is_prime(n, k=10):
    """Test de primalité de Miller-Rabin"""
    if n < 2:
        return False
    if n in [2, 3]:
        return True
    if n % 2 == 0:
        return False
    
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generer_premier(bits):
    """Génère un nombre premier de la taille spécifiée"""
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1
        if is_prime(candidate):
            return candidate

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def modinv(a, m):
    gcd, x, _ = egcd(a, m)
    if gcd != 1:
        return None
    else:
        return x % m

def generer_cles_rsa(bits=2048):
    """Génère des clés RSA valides"""
    print(f"Génération de clés RSA {bits} bits...")
    
   
    p = generer_premier(bits // 2)
    q = generer_premier(bits // 2)
    
    while p == q:
        q = generer_premier(bits // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    
    
    if egcd(e, phi)[0] != 1:
        print("Erreur: e et φ(n) ne sont pas premiers entre eux, regénération...")
        return generer_cles_rsa(bits)
    
    d = modinv(e, phi)
    
    if d is None:
        print("Erreur dans le calcul de d, regénération...")
        return generer_cles_rsa(bits)
    
    
    test = 12345
    chiffre = pow(test, e, n)
    dechiffre = pow(chiffre, d, n)
    
    if test != dechiffre:
        print("Les clés générées ne sont pas valides, regénération...")
        return generer_cles_rsa(bits)
    
    print("✓ Clés RSA générées avec succès")
    return p, q, n, e, d, phi

p, q, n, e, d, phi = generer_cles_rsa(2048)

print(f"Clés générées:")
print(f"p = {p}")
print(f"q = {q}")
print(f"n = {n}")
print(f"e = {e}")
print(f"d = {d}")
print()

# === FONCTIONS RSA ===
def chiffrer(m_int, e, n):
    return pow(m_int, e, n)

def dechiffrer(c_int, d, n):
    return pow(c_int, d, n)

# === PADDING PKCS#1 v1.5 ===
def pkcs1_v15_pad(message: bytes, taille_cle_bits: int) -> bytes:
    k = (taille_cle_bits + 7) // 8
    mlen = len(message)
    
    if mlen > k - 11:
        raise ValueError("Message trop long pour le padding PKCS#1 v1.5")
    
    ps_len = k - mlen - 3
    ps = bytes([random.randint(1, 255) for _ in range(ps_len)])
    padded = b'\x00\x02' + ps + b'\x00' + message
    
    return padded

def pkcs1_v15_unpad(padded: bytes) -> bytes:
    if len(padded) < 11:
        raise ValueError("Message trop court pour un padding valide")
    
    if padded[0] != 0x00 or padded[1] != 0x02:
        raise ValueError("Padding invalide (ne commence pas par 00 02)")
    
    sep_index = None
    for i in range(2, len(padded)):
        if padded[i] == 0x00:
            sep_index = i
            break
    
    if sep_index is None:
        raise ValueError("Séparateur 0x00 non trouvé")
    
    if sep_index < 10:
        raise ValueError("Padding string trop court")
    
    return padded[sep_index + 1:]

# === FONCTIONS DE HAUT NIVEAU ===
def rsa_chiffrer(message: str) -> int:
    message_bytes = message.encode('utf-8')
    taille_cle_bits = n.bit_length()
    padded = pkcs1_v15_pad(message_bytes, taille_cle_bits)
    m_int = int.from_bytes(padded, byteorder='big')
    c = chiffrer(m_int, e, n)
    return c

def rsa_dechiffrer(c: int) -> str:
    decrypted_int = dechiffrer(c, d, n)
    taille_cle_bits = n.bit_length()
    k = (taille_cle_bits + 7) // 8
    
    try:
        decrypted_bytes = decrypted_int.to_bytes(k, byteorder='big')
    except OverflowError:
        decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big')
    
    unpadded = pkcs1_v15_unpad(decrypted_bytes)
    return unpadded.decode('utf-8')

# === TEST ===
if __name__ == "__main__":
    message = "Rsa"
    print(f"Message original : {message}")
    print(f"Taille de la clé : {n.bit_length()} bits ({(n.bit_length() + 7) // 8} octets)")
    
    try:
        # Chiffrement
        c = rsa_chiffrer(message)
        print(f"Message chiffré (entier) : {c}")
        
        # Déchiffrement
        decrypted = rsa_dechiffrer(c)
        print(f"Message déchiffré : {decrypted}")
        
        # Vérification
        if message == decrypted:
            print("✓ Chiffrement/déchiffrement réussi !")
        else:
            print("✗ Erreur : les messages ne correspondent pas")
            
    except Exception as ex:
        print(f"Erreur lors du chiffrement/déchiffrement : {ex}")
        import traceback
        traceback.print_exc()