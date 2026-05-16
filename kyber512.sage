import os, hashlib, struct, time, ctypes, fcntl

# ══════════════════════════════════════════════════════════════════════════════
# KYBER-512  —  Implémentation SageMath commentée ligne par ligne
# Référence officielle : CRYSTALS-Kyber (FIPS 203 / NIST PQC Round 3)
# https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf
# ══════════════════════════════════════════════════════════════════════════════


# ──────────────────────────────────────────────────────────────────────────────
# §1 PARAMÈTRES GLOBAUX
# ──────────────────────────────────────────────────────────────────────────────

n   = 256    
q   = 3329   
K   = 2      

eta1 = 3     
eta2 = 2     
DU  = 10     
DV  = 4      


# ──────────────────────────────────────────────────────────────────────────────
# §2 CONSTRUCTION DE L'ANNEAU Rq = Zq[x] / (x^n + 1)
# ──────────────────────────────────────────────────────────────────────────────

Zq = GF(q)                       
Px = PolynomialRing(Zq, 'x')     
x  = Px.gen()                    
Rq = Px.quotient(x^n + 1, 'a')  


# ──────────────────────────────────────────────────────────────────────────────
# §3 CONVERSIONS POLYNÔME ↔ LISTE
# ──────────────────────────────────────────────────────────────────────────────

def to_rq(lst):
    return Rq(Px(list(lst)))           


def from_rq(p):
    c = p.lift().list()                
    c += [0] * (n - len(c))           
    return [int(v) for v in c]        


# ── Constantes Linux perf_event (x86-64) ─────────────────────────────────────
_NR_PERF_EVENT_OPEN       = 298    # numéro du syscall perf_event_open (x86-64)
_PERF_TYPE_HARDWARE       = 0      # famille : compteurs matériels PMU
_PERF_COUNT_HW_CPU_CYCLES = 0      # config  : compteur de cycles CPU
_PERF_EVENT_IOC_RESET     = 0x2403 # ioctl : remet le compteur à zéro
_PERF_EVENT_IOC_ENABLE    = 0x2400 # ioctl : démarre le comptage
_PERF_EVENT_IOC_DISABLE   = 0x2401 # ioctl : arrête le comptage


def _open_hw_cycle_counter():
    try:
        # Construit la structure perf_event_attr en mémoire
        attr = bytearray(128)
        struct.pack_into('<I', attr,  0, _PERF_TYPE_HARDWARE)
        struct.pack_into('<I', attr,  4, 128)
        struct.pack_into('<Q', attr,  8, _PERF_COUNT_HW_CPU_CYCLES)
        # bit0=disabled | bit5=exclude_kernel | bit6=exclude_hv
        struct.pack_into('<Q', attr, 40, (1 << 0) | (1 << 5) | (1 << 6))

        # Crée un buffer ctypes depuis les octets (évite c_char_p qui peut
        # être tronqué sur les octets nuls internes de la structure)
        attr_buf = ctypes.create_string_buffer(bytes(attr), 128)

        _libc = ctypes.CDLL(None, use_errno=True)

        # ── CORRECTION CLEF : déclarer restype et argtypes ────────────────
        # Sans cette déclaration, ctypes passe les entiers en 32 bits sur
        # certaines ABI (macOS, MSVC) ou génère un ArgumentError sur les
        # types incompatibles. On force explicitement chaque type.
        _libc.syscall.restype  = ctypes.c_long          # valeur de retour : fd (long)
        _libc.syscall.argtypes = [
            ctypes.c_long,                               # numéro du syscall
            ctypes.c_char_p,                             # *attr (pointeur struct)
            ctypes.c_int,                                # pid
            ctypes.c_int,                                # cpu
            ctypes.c_int,                                # group_fd
            ctypes.c_ulong,                              # flags
        ]

        fd = _libc.syscall(
            ctypes.c_long(_NR_PERF_EVENT_OPEN),
            attr_buf,                                    # pointeur vers perf_event_attr
            ctypes.c_int(0),                             # pid = 0 : processus courant
            ctypes.c_int(-1),                            # cpu = -1 : tous les cœurs
            ctypes.c_int(-1),                            # group_fd = -1 : pas de groupe
            ctypes.c_ulong(8),                           # flags = PERF_FLAG_FD_CLOEXEC
        )
        return int(fd) if int(fd) >= 0 else None         # fd valide ou None si erreur

    except Exception:
        # Capture tout : ArgumentError ctypes, OSError, syscall absent sur macOS…
        return None


# Tentative d'ouverture au démarrage — échec silencieux → fallback automatique
_PERF_FD            = _open_hw_cycle_counter()
HW_CYCLES_AVAILABLE = _PERF_FD is not None   # True → PMU dispo ; False → fallback


def _read_perf_fd():
    return struct.unpack('<Q', os.pread(_PERF_FD, 8, 0))[0]


def measure_cycles(fn):
    if HW_CYCLES_AVAILABLE:
        fcntl.ioctl(_PERF_FD, _PERF_EVENT_IOC_RESET,   0)  # remet à 0
        fcntl.ioctl(_PERF_FD, _PERF_EVENT_IOC_ENABLE,  0)  # démarre
        fn()
        fcntl.ioctl(_PERF_FD, _PERF_EVENT_IOC_DISABLE, 0)  # arrête
        return _read_perf_fd()                               # cycles réels
    else:
        t0 = time.perf_counter_ns()
        fn()
        return ns_to_cycles(time.perf_counter_ns() - t0, CPU_FREQ_HZ)


# ── Fallback : fréquence CPU (utilisée uniquement si PMU indisponible) ────────

def get_cpu_frequency_hz():
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if 'cpu MHz' in line:
                    return float(line.split(':')[1].strip()) * 1_000_000
    except Exception:
        pass
    return 2_500_000_000


def ns_to_cycles(nanoseconds, freq_hz):
    return int(nanoseconds * freq_hz / 1_000_000_000)


CPU_FREQ_HZ = get_cpu_frequency_hz()


# ──────────────────────────────────────────────────────────────────────────────
# §5 DISTRIBUTION BINOMIALE CENTRÉE (CBD)
#    Génère des polynômes à petits coefficients à partir d'un seed (bruit Kyber)
# ──────────────────────────────────────────────────────────────────────────────

def centered_binomial(eta, seed, nonce):
    nb   = int((2 * eta * n + 7) // 8)  # Nombre d'octets à générer : ⌈(2η·256)/8⌉
    raw  = hashlib.shake_256(             # SHAKE-256 = XOF (eXtendable Output Function) utilisée comme PRF
               seed + struct.pack('<H', int(nonce))  # Concatène seed || nonce en little-endian 16 bits
           ).digest(nb)                              # Produit exactement nb octets pseudo-aléatoires

    # Développe chaque octet en 8 bits individuels (LSB en premier, conforme spec)
    bits = [(byte >> i) & 1 for byte in raw for i in range(8)]

    # Pour chaque coefficient i : c_i = Σ(a_j) - Σ(b_j) avec a_j, b_j ∈ {0,1}
    # Cela donne une distribution binomiale centrée dans {-η, …, +η}
    coeffs = [
        (sum(bits[2*eta*i + j]       for j in range(eta)) -   # Σ des η premiers bits (partie +)
         sum(bits[2*eta*i + eta + j] for j in range(eta))) % q # Σ des η suivants bits (partie -)
        for i in range(n)                                       # Un coefficient par indice i ∈ [0,255]
    ]
    return to_rq(coeffs)  # Retourne le polynôme dans Rq


# ──────────────────────────────────────────────────────────────────────────────
# §6 GÉNÉRATION DE LA MATRICE PUBLIQUE A ∈ Rq^{K×K}
#    Dérivée déterministiquement depuis la graine publique ρ via SHAKE-128
# ──────────────────────────────────────────────────────────────────────────────

def gen_matrix(rho):
    entries = []                          # Liste plate pour stocker les K² polynômes
    for i in range(K):                    # Indice ligne de la matrice
        for j in range(K):                # Indice colonne de la matrice
            # SHAKE-128 avec domaine séparé : ρ || [i, j] → flux de 512 octets
            seed   = hashlib.shake_128(rho + bytes([i, j])).digest(int(n * 2))
            # Interprète chaque paire d'octets comme un entier 16 bits little-endian
            # réduit mod q → coefficients uniformes dans [0, q-1]
            coeffs = [(seed[2*l] | (seed[2*l+1] << 8)) % q for l in range(n)]
            entries.append(to_rq(coeffs)) # Ajoute le polynôme à la liste

    return Matrix(Rq, K, K, entries)      # Construit la matrice K×K sur Rq (objet SageMath)


# ──────────────────────────────────────────────────────────────────────────────
# §7 COMPRESSION / DÉCOMPRESSION
#    Réduit la taille du chiffré en tronquant des bits de précision
# ──────────────────────────────────────────────────────────────────────────────

def compress(p, d):
    return [
        int(round(Integer(c) * (1 << d) / q)) % (1 << d)  # Arrondi au plus proche puis mod 2^d
        for c in from_rq(p)                                 # Itère sur les 256 coefficients
    ]


def decompress(lst, d):
    return to_rq([
        int(round(Integer(c) * q / (1 << d))) % q  # Remonte l'entier d bits vers [0, q-1]
        for c in lst                                 # Itère sur les n valeurs compressées
    ])


# ──────────────────────────────────────────────────────────────────────────────
# §8 ENCODAGE / DÉCODAGE DU MESSAGE BINAIRE
#    Plonge 32 octets (256 bits) dans Rq comme ±q/4
# ──────────────────────────────────────────────────────────────────────────────

def encode_msg(m):
    bits = int.from_bytes(m, 'little')   # Lit les 256 bits en little-endian (bit 0 = LSB de m[0])
    return to_rq([
        ((bits >> i) & 1) * int(round(q / 2)) % q  # Bit i=0 → coeff 0, bit i=1 → coeff 1665
        for i in range(n)                            # Un coefficient par bit
    ])


def decode_msg(p):
    coeffs = from_rq(p)                   # Récupère les 256 coefficients entiers
    bits   = sum(
        1 << i                            # Met le bit i à 1 si le coefficient est "proche" de q/2
        for i, c in enumerate(coeffs)
        if q // 4 < c <= 3 * q // 4       # Seuil : intervalle ]q/4, 3q/4] = ]832, 2497]
    )
    return int(bits).to_bytes(int(n // 8), 'little')  # Retourne 32 octets en little-endian


# ──────────────────────────────────────────────────────────────────────────────
# §9 SÉRIALISATION POLYNÔME ↔ OCTETS
#    Empaquète n coefficients de d bits chacun en une séquence d'octets
# ──────────────────────────────────────────────────────────────────────────────

def poly_to_bytes(lst, d):
    val = sum(int(lst[i]) << int(i * d) for i in range(n))  # Concatène les d bits de chaque coeff
    return val.to_bytes(int((n * d + 7) // 8), 'little')    # Convertit le grand entier en octets


def bytes_to_poly(data, d):
    val = int.from_bytes(data, 'little')          # Lit les octets comme un grand entier little-endian
    return [
        (val >> int(i * d)) & int((1 << d) - 1)  # Extrait les d bits à la position i·d
        for i in range(n)                          # Un entier par coefficient
    ]


# ──────────────────────────────────────────────────────────────────────────────
# §10 GÉNÉRATION DE CLÉS — KeyGen
# ──────────────────────────────────────────────────────────────────────────────

def keygen(seed=None):
    if seed is not None:
        # ── Mode déterministe (compatible vecteurs NIST KAT) ──────────────────
        assert len(seed) == 32, #Le seed doit faire exactement 32 octets"
        h   = hashlib.sha3_512(seed).digest()  # SHA3-512 : 64 octets = ρ (32) || σ (32)
        rho = h[:32]                            # Première moitié : graine publique de la matrice A
        sigma = h[32:]                          # Deuxième moitié : graine secrète pour s et e
    else:
        # ── Mode aléatoire (usage normal) ─────────────────────────────────────
        rho   = os.urandom(32)   # 32 octets aléatoires pour la matrice publique A
        sigma = os.urandom(32)   # 32 octets aléatoires pour les vecteurs secrets

    A = gen_matrix(rho)          # Génère la matrice publique A ∈ Rq^{K×K} depuis ρ

    # Génère le vecteur secret s avec nonces 0, 1, …, K-1
    s = vector(Rq, [centered_binomial(eta1, sigma, i)     for i in range(K)])

    # Génère le vecteur d'erreur e avec nonces K, K+1, …, 2K-1 (séparé de s)
    e = vector(Rq, [centered_binomial(eta1, sigma, K + i) for i in range(K)])

    t = A * s + e                # Calcul de la clé publique : t = A·s + e  (dans Rq^K)

    return (rho, t), s           # Retourne (pk, sk) : pk=(ρ,t) publique, sk=s secrète


# ──────────────────────────────────────────────────────────────────────────────
# §11 ENCAPSULATION — Encaps
# ──────────────────────────────────────────────────────────────────────────────

def encaps(pk):
    rho, t = pk                  # Décompacte la clé publique : ρ (matrice) et t (vecteur)
    m  = os.urandom(32)          # Message aléatoire m ∈ {0,1}^256 (32 octets)

    A  = gen_matrix(rho)         # Reconstruit la matrice publique A depuis ρ

    # Génère les vecteurs de randomness depuis m (nonces distincts de keygen)
    r  = vector(Rq, [centered_binomial(eta1, m, i)     for i in range(K)])      # Nonces 0…K-1
    e1 = vector(Rq, [centered_binomial(eta2, m, K + i) for i in range(K)])      # Nonces K…2K-1
    e2 = centered_binomial(eta2, m, 2 * K)                                       # Nonce 2K

    u  = A.T * r + e1                                # u = Aᵀ·r + e1 ∈ Rq^K (première partie du chiffré)
    v  = t.dot_product(r) + e2 + encode_msg(m)       # v = tᵀ·r + e2 + encode(m) ∈ Rq (deuxième partie)

    # Sérialise u : K polynômes compressés sur DU=10 bits chacun
    ct  = b''.join(poly_to_bytes(compress(u[i], DU), DU) for i in range(K))
    # Ajoute v compressé sur DV=4 bits
    ct += poly_to_bytes(compress(v, DV), DV)

    # Dérive la clé partagée : K = SHA3-256(m || SHA3-256(ct))
    # Le hash de ct lie la clé au chiffré (protection contre les attaques par substitution)
    K_sym = hashlib.sha3_256(m + hashlib.sha3_256(ct).digest()).digest()

    return ct, K_sym             # Retourne le chiffré ct et la clé partagée K_sym


# ──────────────────────────────────────────────────────────────────────────────
# §12 DÉCAPSULATION — Decaps
# ──────────────────────────────────────────────────────────────────────────────

def decaps(sk, pk, ct):
    bu = (n * DU) // 8           # Taille en octets d'un polynôme u compressé sur DU bits

    # Désérialise et décompresse le vecteur u (K polynômes)
    u  = vector(Rq, [
        decompress(bytes_to_poly(ct[i*bu:(i+1)*bu], DU), DU)  # Tranche i·bu à (i+1)·bu
        for i in range(K)
    ])

    # Désérialise et décompresse le polynôme v (reste du chiffré)
    v  = decompress(bytes_to_poly(ct[K*bu:], DV), DV)

    # Retrouve m' : v − sᵀ·u = encode(m) + (erreur), puis decode arrondit à m
    m2 = decode_msg(v - sk.dot_product(u))

    # Dérive la clé partagée de la même façon qu'à l'encapsulation
    return hashlib.sha3_256(m2 + hashlib.sha3_256(ct).digest()).digest()


# ──────────────────────────────────────────────────────────────────────────────
# §13 MÉTRIQUES DE TAILLE
# ──────────────────────────────────────────────────────────────────────────────

def get_public_key_size(pk):
    rho, t     = pk                        # Décompacte la clé publique
    taille_rho = len(rho)                  # ρ toujours 32 octets
    taille_t   = int(K * n * 12 // 8)     # K=2 vecteurs × 256 coeffs × 12 bits ÷ 8 = 768 octets
    return taille_rho + taille_t           # Total : 32 + 768 = 800 octets pour Kyber-512


def get_secret_key_size(sk):
    taille_s = int(K * n * 12 // 8)       # K=2 polynômes × 256 coeffs × 12 bits ÷ 8 = 768 octets
    return taille_s                         # Retourne 768 octets pour Kyber-512


def get_ciphertext_size():
    taille_u = int(K * n * DU // 8)        # 2 × 256 × 10 ÷ 8 = 640 octets
    taille_v = int(n * DV // 8)            # 256 × 4 ÷ 8 = 128 octets
    return taille_u + taille_v             # Total : 768 octets pour Kyber-512


# ──────────────────────────────────────────────────────────────────────────────
# §14 SÉRIALISATION / DÉSÉRIALISATION DES CLÉS
#    Pour compatibilité avec l'implémentation officielle C de CRYSTALS-Kyber
# ──────────────────────────────────────────────────────────────────────────────

def serialize_poly_12bit(poly):
    coeffs = from_rq(poly)                          # Liste de 256 coefficients entiers [0, q-1]
    val    = sum(int(coeffs[i]) << (12 * i) for i in range(n))  # Empaquète sur 12 bits LSB-first
    return val.to_bytes(int(n * 12 // 8), 'little') # 384 octets en little-endian


def deserialize_poly_12bit(data):
    val    = int.from_bytes(data, 'little')          # Grand entier little-endian
    coeffs = [(val >> (12 * i)) & 0xFFF for i in range(n)]  # Extrait 12 bits par coeff (masque 0xFFF)
    return to_rq(coeffs)                             # Retourne le polynôme dans Rq


def serialize_public_key(pk):
    rho, t = pk                                           # Décompacte clé publique
    t_bytes = b''.join(serialize_poly_12bit(t[i])         # Encode chaque polynôme de t sur 384 octets
                       for i in range(K))
    return t_bytes + rho                                  # Concatène t_encodé puis ρ (ordre spec)


def deserialize_public_key(data):
    bpt = int(n * 12 // 8)                                # Taille d'un polynôme encodé = 384 octets
    t   = vector(Rq, [deserialize_poly_12bit(data[i*bpt:(i+1)*bpt])  # Décode les K polynômes
                      for i in range(K)])
    rho = data[K * bpt:]                                  # Derniers 32 octets = ρ
    return rho, t                                          # Retourne la clé publique reconstituée


def serialize_secret_key(sk):
    return b''.join(serialize_poly_12bit(sk[i]) for i in range(K))  # Encode K polynômes de s


def deserialize_secret_key(data):
    bpt = int(n * 12 // 8)                                # 384 octets par polynôme
    return vector(Rq, [deserialize_poly_12bit(data[i*bpt:(i+1)*bpt])  # Décode K polynômes
                       for i in range(K)])


# ──────────────────────────────────────────────────────────────────────────────
# §15 VECTEURS DE TEST OFFICIEL (KAT — Known Answer Tests)
#    Permet de vérifier la compatibilité avec l'implémentation de référence NIST
# ──────────────────────────────────────────────────────────────────────────────

def run_kat_test():
    seed_fixe = bytes.fromhex(                                  # Seed KAT standard (premier vecteur NIST)
        "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1")
    seed_fixe = seed_fixe[:32]                                  # Tronque à 32 octets si nécessaire

    pk, sk = keygen(seed=seed_fixe)                             # Génération déterministe
    pk_bytes = serialize_public_key(pk)                         # Sérialise en bytes
    sk_bytes = serialize_secret_key(sk)                         # Sérialise en bytes

    print("── Vecteur de test KAT (seed fixe) ──")
    print(f"  pk (hex, 32 premiers octets) : {pk_bytes[:32].hex()}")  # Affiche début pk
    print(f"  sk (hex, 32 premiers octets) : {sk_bytes[:32].hex()}")  # Affiche début sk
    print("  → Comparer avec la sortie de l'implémentation C officielle")
    return pk_bytes, sk_bytes


# ──────────────────────────────────────────────────────────────────────────────
# §16 BENCHMARKS EN CYCLES CPU
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
# §16 BENCHMARKS EN CYCLES CPU
# ──────────────────────────────────────────────────────────────────────────────

def _collect_cycles(fn, iterations, warmup=3):
    for _ in range(warmup):
        fn()

    raw = [measure_cycles(fn) for _ in range(iterations)]

    raw_sorted = sorted(raw)
    return {
        'avg' : int(sum(raw) / iterations),
        'med' : raw_sorted[iterations // 2],   # médiane : robuste aux outliers ponctuels
        'min' : raw_sorted[0],                  # minimum : cas sans interférence OS
        'max' : raw_sorted[-1],                 # maximum : pire cas scheduleur
    }


def benchmark_keygen(iterations=100):
    return _collect_cycles(lambda: keygen(), iterations)


def benchmark_timings(pk, sk, ct, iterations=100):
    stats_enc = _collect_cycles(lambda: encaps(pk),         iterations)
    stats_dec = _collect_cycles(lambda: decaps(sk, pk, ct), iterations)
    return stats_enc, stats_dec


# ══════════════════════════════════════════════════════════════════════════════
# §17 PROGRAMME PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':

    # ── Cycle de vie complet : keygen → encaps → decaps ───────────────────────
    pk, sk = keygen()              # Génération aléatoire de la paire de clés
    ct, K1 = encaps(pk)            # Alice encapsule : produit le chiffré et la clé partagée K1
    K2     = decaps(sk, pk, ct)    # Bob décapsule : retrouve la clé partagée K2

    # ── Vérification de l'exactitude ──────────────────────────────────────────
    print("══════════════════════════════════════")
    print("  KYBER-512  —  Vérification")
    print("══════════════════════════════════════")
    print(f"Clé Alice        : {K1.hex()[:32]} …")   # Affiche les 16 premiers octets de K1
    print(f"Clé Bob          : {K2.hex()[:32]} …")   # Affiche les 16 premiers octets de K2
    print(f"Clés identiques  : {K1 == K2}")           # Doit afficher True

    # ── Métriques de taille ───────────────────────────────────────────────────
    print("\n══════════════════════════════════════")
    print("  Tailles des éléments")
    print("══════════════════════════════════════")
    print(f"Clé publique  (pk) : {get_public_key_size(pk):>6} octets  (théorique : {K*n*12//8 + 32})")
    print(f"Clé secrète   (sk) : {get_secret_key_size(sk):>6} octets  (théorique : {K*n*12//8})")
    print(f"Chiffré       (ct) : {len(ct):>6} octets  (théorique : {get_ciphertext_size()})")
    print(f"Clé partagée (sym) : {len(K1):>6} octets  (SHA3-256 = 32 octets)")

    # ── Sérialisation / compatibilité officielle ──────────────────────────────
    print("\n══════════════════════════════════════")
    print("  Sérialisation (compatibilité NIST)")
    print("══════════════════════════════════════")
    pk_bytes = serialize_public_key(pk)                       # Sérialise pk en 800 octets
    sk_bytes = serialize_secret_key(sk)                       # Sérialise sk en 768 octets
    print(f"pk sérialisé  : {len(pk_bytes)} octets → {pk_bytes[:8].hex()} …")
    print(f"sk sérialisé  : {len(sk_bytes)} octets → {sk_bytes[:8].hex()} …")

    # Vérifie que la désérialisation reconstituée donne le même résultat
    pk2 = deserialize_public_key(pk_bytes)   # Désérialise pk
    sk2 = deserialize_secret_key(sk_bytes)   # Désérialise sk
    K3  = decaps(sk2, pk2, ct)               # Décapsule avec les clés reconstituées
    print(f"Round-trip pk/sk OK : {K3 == K2}")  # Doit afficher True

    # ── Vecteur KAT ───────────────────────────────────────────────────────────
    print()
    run_kat_test()

    # ── Benchmarks en cycles CPU ──────────────────────────────────────────────
    print("\n══════════════════════════════════════")
    print("  Benchmarks (100 itérations)")
    print("══════════════════════════════════════")
    if HW_CYCLES_AVAILABLE:
        print("Mode : compteur PMU matériel (perf_event_open) ✓  — cycles stables")
    else:
        print("Mode : fallback time.perf_counter_ns()  — cycles estimés (variables)")
        print("  → Pour activer le PMU : sudo sysctl kernel.perf_event_paranoid=1")
    print("Calcul en cours …")

    kg       = benchmark_keygen(iterations=100)
    enc, dec = benchmark_timings(pk, sk, ct, iterations=100)

    def _fmt(label, s):
        print(f"\n── {label} ──")
        print(f"  Médiane : {s['med']:>12,} cycles  ← référence stable")
        print(f"  Moyenne : {s['avg']:>12,} cycles")
        print(f"  Minimum : {s['min']:>12,} cycles  (sans interférence OS)")
        print(f"  Maximum : {s['max']:>12,} cycles  (pire cas scheduleur)")

    _fmt("Génération de clés (KeyGen)", kg)
    _fmt("Encapsulation", enc)
    _fmt("Décapsulation", dec)

    print(f"\n── Récapitulatif (médiane) ──")
    print(f"  KeyGen        : {kg['med']:>12,} cycles")
    print(f"  Encapsulation : {enc['med']:>12,} cycles")
    print(f"  Décapsulation : {dec['med']:>12,} cycles")
    print(f"  Rapport enc/dec : {enc['med'] / dec['med']:.2f}×")
