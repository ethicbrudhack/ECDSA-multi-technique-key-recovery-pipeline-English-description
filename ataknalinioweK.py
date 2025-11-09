#!/usr/bin/env python3
import hashlib
import ecdsa
import base58
import bech32
from ecdsa.numbertheory import inverse_mod
import numpy as np
from sympy import symbols, Eq, solve
from functools import lru_cache
from multiprocessing import freeze_support
import random
import xgboost as xgb
from deap import base, creator, tools, algorithms
import logging
import math
import copy

# Ustawienia logowania – zapisywanie wyników do pliku
logging.basicConfig(filename="optimization.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Parametry ECDSA
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ----------------------------------------------------------------------------
# Funkcja pomocnicza do dekodowania adresu (do porównania)
def get_hash160_from_address(addr):
    try:
        if addr.startswith("1") or addr.startswith("3"):  # P2PKH lub P2SH
            decoded = base58.b58decode_check(addr)
            return decoded[1:].hex()
        elif addr.startswith("bc1"):  # Bech32 (SegWit)
            hrp, data = bech32.bech32_decode(addr)
            if data is None:
                return None
            converted = bech32.convertbits(data[1:], 5, 8, False)
            return bytes(converted).hex()
    except Exception as e:
        print("Błąd dekodowania adresu:", e, flush=True)
        return None

# ----------------------------------------------------------------------------
# Funkcja zwracająca zestaw transakcji – im więcej, tym lepiej!
def get_real_transactions():
    return [
        { "r": int("1c972a7f8621aba86f0d56e805956cde2dfde06938df15056c42cf38ebc9dc45", 16),
  "s": int("2dbeac4704c4f386f928b7732a9477552c2ad40c41679d03b211ff2e3c2e14f0", 16),
  "z": int("e602f339d476c5b93fae6749db670e5298e9739228967eaa59daafade09c1fa2", 16) },
{ "r": int("916ff5faa2f5fd40db2ea8972b1edfe6a63f13e2294c6e5cbd86149b4066e0ba", 16),
  "s": int("294fd52259ec8864788f0218927d00ac8e1d6b5380da5ea520745899e860ceaa", 16),
  "z": int("d51a797b9b83cbdc956d092dd1d9174c9929f6a5704ce951eeba3447f3c55fd2", 16) },
{ "r": int("d8e2d92d3fca2a3293ed2e57c80a8db40069da2229225756b77de2f967baa1fb", 16),
  "s": int("6f2dc5ce39475b4c98ae27285a36939aadf19e38b3845c57400ef08326d24d23", 16),
  "z": int("cc5260cf9f0c439f2847dae4560a63f62da6fb6682ed77df872076f0f0aafd34", 16) },
{ "r": int("c1c83fb6cf745bf4eb518b4683dadb2e6eeab031fde8f7f27ff0da49a182d317", 16),
  "s": int("044812973948efef2db516c93f7eb4ee8d224ccc0181d3794fc3704ae3324a8b", 16),
  "z": int("ac6ede455f205ac41a75ce9f1a88cc625a11a3e6b377531096074cbcdbf97a67", 16) },
{ "r": int("5ebecec888b158797ded9ebc1421b4797d4077c2e16945f45361ac33f6abf41b", 16),
  "s": int("340050758fd9de606d45383f63f1b236a7a47318c595e99c910f4b943a88a364", 16),
  "z": int("5429e50aa800fe787d59bc03594476c704c86ce7b58060025ffe9ee6c2658273", 16) },
{ "r": int("4122285f136a320f7c703b3e426c59238918d9109e7c3941fc6a0b6adf5207f7", 16),
  "s": int("1e93eb84918f74f5a26d32366907af8c6ab9e1942b9efb6d935dbe178d06e9ff", 16),
  "z": int("19b517590993c4c3c4a39a516b97eefb1f65c81be9ba251c34a573632b8ba654", 16) },
{ "r": int("27c90531406bbf08bd6325b06fe0ac32e61a66f3d8b2762a7bf2ac6c13e76ddc", 16),
  "s": int("096ddba45472fe9cca48753e7ca89b70ef358badbd458e08ef77fc79a85d7ae8", 16),
  "z": int("c29d8e7add11ca847ca90aebc44821571aa0224609a534374aedb3680a663b9e", 16) },
{ "r": int("bde208ab14f08c144c476ad0913b819ac85edb0817648f7a9c7bfba6ff3d2ae4", 16),
  "s": int("361cd7453471392f166f75fae077c6eab3bb87b3cf097e6c8e821b647adfa2c8", 16),
  "z": int("c2aed3ced357dea4d71da93173fe5fcdf9a3ffa5f2112c6c0d7268483aefe916", 16) },
{ "r": int("d49081dbc8456347d95a13f012f952ba515c3a2d7e6a217a45d524231f9e73be", 16),
  "s": int("129b6d94862d072a25c381264f280ed4a72d6a6e72d14971d0d7be4339c91893", 16),
  "z": int("6fcff0a703f2af14a94588598762ac7920a75be3cf51bba530d54b3ae1482ff1", 16) },
{ "r": int("ba4cbf9de2d8f8cec6ace7fd8fde68b6bb247a3494618f0684a07542557d8dd1", 16),
  "s": int("6a8dd246334494bbb852c19e885af8b951e90983438cd6eef7daf01ba2a21453", 16),
  "z": int("639a5415a446859710e6e65b6ece3731a74be0e3a8a7486c95c01b32b410ebd8", 16) },
{ "r": int("d586bc4612c60c1c7720d7abe39ab1495f85741b1c307973064732c72ed00216", 16),
  "s": int("56bf08497eefcec00fac3a304d3ddcc0c7555a278834ed62cc5f40459842959a", 16),
  "z": int("995732b0b9ebf1e5f645ef1883fb6b5bf14b565f8a628a63448f0c164783bbfc", 16) },
{ "r": int("ac2a02121824dac496f3579e06538339b0d195e72f7bd3ca43865825df9b5920", 16),
  "s": int("7c90e85461651eeef17cfb57aa0d881360b5958e6b16922d3042695303838312", 16),
  "z": int("9c69df8613fa938611a068653e340813fcdc7a7d161d622fc1323edbba4f20a6", 16) },
{ "r": int("64669b93916da2479cf05d1afb934e6ba1f8a5d075653d78ffda73aea58f0dc7", 16),
  "s": int("165cce6cbd3319962ad293274ded1c55f32ce1140f21de151f374cac43c14867", 16),
  "z": int("9d01f18b10c1c8c69fa9a1214b72fec7715fc805b1aac58b7a619c9086610277", 16) },
{ "r": int("b598a96eba7b6c446c9952dadaf4fe47cc8790fcb4fe213f057ee164ca6d6d27", 16),
  "s": int("7c6713418c03c04a4fe1706152689d8af771d750f774d651d01ddc156fc66350", 16),
  "z": int("eeaa4adb9c2e6f01b6068d02b210d103e0e5f86cf85539fc36f209d799197cc1", 16) },
{ "r": int("11952e29e6f6c922cff457ecd9f321ebad78897763c215432dbebb6507035712", 16),
  "s": int("62679604933a2fadf563edf503e7ed062652168c69f8f9176902a946ef508d15", 16),
  "z": int("846906b9209e880bf423a1bca13544047cf64e9a798eba319323be76c05e02e0", 16) },
{ "r": int("db11356c4e2e5d08928f368fbb90847d6f625f9cc041b4c3d800d72700926e6c", 16),
  "s": int("2379cae59dfa3bc8870e345602c20ed5f7e0828b043f4edabfe200e2c7e58e05", 16),
  "z": int("f894e6eb916cdf90fd48e6e267af1a7b8bdbe2fe2aa04e1d40d42351ee0c1f1a", 16) },
{ "r": int("d3ba3cab814f547073ee20c4aa7359727bc1ab8f21f05482e0c1dc9b49a0291a", 16),
  "s": int("4c66a7756c7515031c29984cc679fc2d4f19774056b8b31d9d7acac9e74483a4", 16),
  "z": int("a840a72c4b32e6420c9ef12acbc407d234fbfc1a876eb439ef22dd06e31a2bbd", 16) },
{ "r": int("983e234fc4998fa10495e28ffd9dc874ee1d9792b82fb196b7caae53cc9a7dc7", 16),
  "s": int("0e09c0b0fe6650c709d8cd0bbf57a8682416c3c947c5026a75656fa64ab22db9", 16),
  "z": int("6b8a40aa6fea5331ed6dfb2308d0bf5287613f14f477df247dc6444ac5474a45", 16) }
    ]

# ----------------------------------------------------------------------------
# Funkcja odzyskująca d (cache'owana)
@lru_cache(maxsize=None)
def recover_d_cached(r, s, z, k):
    try:
        inv_r = inverse_mod(r, n)
    except Exception:
        return None
    d = ((s * k - z) % n) * inv_r % n
    if 1 < d < n:
        return d
    return None

# ----------------------------------------------------------------------------
# Funkcja celu – oblicza wariancję odzyskanych d
def objective(k):
    k_int = int(k % n)
    transactions = get_real_transactions()
    candidate_ds = []
    for tx in transactions:
        d_candidate = recover_d_cached(tx["r"], tx["s"], tx["z"], k_int)
        if d_candidate is None:
            candidate_ds.append(n)  # kara
        else:
            candidate_ds.append(d_candidate)
    error = 0
    for i in range(len(candidate_ds)):
        for j in range(i+1, len(candidate_ds)):
            error += abs(candidate_ds[i] - candidate_ds[j])
    return error, candidate_ds

# ----------------------------------------------------------------------------
# Model ML – ekstrakcja cech, trening i predykcja
def extract_features(signatures):
    features = []
    for i, sig in enumerate(signatures):
        r_norm = sig["r"] / n
        s_norm = sig["s"] / n
        z_norm = sig["z"] / n
        log_r = math.log(sig["r"] + 1)
        log_s = math.log(sig["s"] + 1)
        log_z = math.log(sig["z"] + 1)
        if i > 0:
            dr = abs(sig["r"] - signatures[i-1]["r"]) / n
            ds = abs(sig["s"] - signatures[i-1]["s"]) / n
            dz = abs(sig["z"] - signatures[i-1]["z"]) / n
        else:
            dr = ds = dz = 0
        features.append([r_norm, s_norm, z_norm, log_r, log_s, log_z, dr, ds, dz])
    return np.array(features, dtype=float)

def train_ml_model(signatures):
    X = extract_features(signatures)
    y = np.array([random.randint(1, n-1) for _ in signatures], dtype=float) / n
    model = xgb.XGBRegressor(objective="reg:squarederror", n_estimators=100)
    model.fit(X, y)
    return model

def predict_k_with_ml(model, signatures):
    X = extract_features(signatures)
    predicted_k = model.predict(X)
    predicted_k = [max(1, min(n-1, int(round(k * n)))) for k in predicted_k]
    return predicted_k

# ----------------------------------------------------------------------------
# Algorytm genetyczny
creator.create("FitnessMin", base.Fitness, weights=(-1.0,))
creator.create("Individual", list, fitness=creator.FitnessMin)

def eval_k(individual):
    k = individual[0]
    err, ds = objective(k)
    logging.info(f"Kandydat k: {k} | Błąd: {err} | d: {ds}")
    return (err,)

def genetic_algorithm_k(signatures, generations=100, population_size=20):
    toolbox = base.Toolbox()
    toolbox.register("attr_int", random.randint, 1, n-1)
    toolbox.register("individual", tools.initRepeat, creator.Individual, toolbox.attr_int, 1)
    toolbox.register("population", tools.initRepeat, list, toolbox.individual)
    toolbox.register("evaluate", eval_k)
    toolbox.register("mate", tools.cxUniform, indpb=0.5)
    toolbox.register("mutate", tools.mutGaussian, mu=0, sigma=n//1000, indpb=0.2)
    toolbox.register("select", tools.selTournament, tournsize=3)

    pop = toolbox.population(n=population_size)
    algorithms.eaSimple(pop, toolbox, cxpb=0.5, mutpb=0.2, ngen=generations, verbose=True)
    best_ind = tools.selBest(pop, 1)[0][0]
    logging.info(f"Najlepsze k znalezione przez algorytm genetyczny: {best_ind}")
    return best_ind

# ----------------------------------------------------------------------------
# Simulated annealing – lokalne przeszukiwanie otoczenia k
def simulated_annealing_k(initial_k, T_init=10000, alpha=0.99, iterations=500):
    current_k = initial_k
    current_error, _ = objective(current_k)
    best_k = current_k
    best_error = current_error
    T = T_init
    for i in range(iterations):
        delta = random.randint(-int(T), int(T))
        new_k = (current_k + delta) % n
        new_error, _ = objective(new_k)
        if new_error < current_error:
            current_k, current_error = new_k, new_error
            if new_error < best_error:
                best_k, best_error = new_k, new_error
        else:
            if random.random() < math.exp(-(new_error - current_error) / T):
                current_k, current_error = new_k, new_error
        T = max(1, T * alpha)
    logging.info(f"Simulated annealing: najlepsze k = {best_k} z błędem {best_error}")
    return best_k

# ----------------------------------------------------------------------------
# Brute-force refinement – lokalne przeszukiwanie otoczenia k
def refine_candidate_k(candidate_k, search_range=1000):
    best_k = candidate_k
    best_error, _ = objective(candidate_k)
    for delta in range(-search_range, search_range + 1):
        new_k = (candidate_k + delta) % n
        error, _ = objective(new_k)
        if error < best_error:
            best_error = error
            best_k = new_k
    logging.info(f"Refinement: ulepszone k = {best_k} z błędem {best_error}")
    return best_k

# ----------------------------------------------------------------------------
# Placeholder dla lattice attack – klasyczna metoda, gdy nonce są słabe
def lattice_attack(signatures):
    print("Uruchamianie metody lattice attack (placeholder)", flush=True)
    # Na potrzeby testów, zwracamy losową wartość całkowitą
    return random.randint(1, n-1)

# ----------------------------------------------------------------------------
# Generowanie adresów z odzyskanego klucza prywatnego
def generate_addresses_from_private_key(d):
    try:
        private_key_bytes = d.to_bytes(32, 'big')
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        pubkey_compressed = sk.get_verifying_key().to_string("compressed")
        pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey_compressed).digest()).digest()
        p2pkh_address = base58.b58encode_check(b'\x00' + pubkey_hash).decode()
        bech32_address = bech32.encode("bc", 0, pubkey_hash)
        nested_script = b'\x00\x14' + pubkey_hash
        nested_hash = hashlib.new('ripemd160', hashlib.sha256(nested_script).digest()).digest()
        nested_p2sh = base58.b58encode_check(b'\x05' + nested_hash).decode()
        return p2pkh_address, bech32_address, nested_p2sh
    except Exception as e:
        print(f"Błąd generowania adresów: {e}", flush=True)
        return None, None, None

# ----------------------------------------------------------------------------
# Mechanizm iteracyjnej poprawy – wyszukiwanie k aż do znalezienia poprawnej pary (d, k)
def iterative_search(target_address, max_iterations=2000):
    signatures = get_real_transactions()
    target_hash160 = get_hash160_from_address(target_address)
    iteration = 0
    best_overall_ds = None
    best_overall_error = float('inf')
    best_overall_k = None

    while iteration < max_iterations:
        print(f"\nIteracja {iteration}: generowanie kandydatów...", flush=True)
        # Generowanie kandydatów k metodami:
        model_ml = train_ml_model(signatures)
        predicted_ks_ml = predict_k_with_ml(model_ml, signatures)
        candidate_k_genetic = genetic_algorithm_k(signatures, generations=50, population_size=10)
        candidate_k_lattice = lattice_attack(signatures)
        
        candidate_ks = set(predicted_ks_ml + [candidate_k_genetic, candidate_k_lattice])
        print(f"Iteracja {iteration}: znaleziono {len(candidate_ks)} kandydatów k", flush=True)
        
        # Dla najlepszego dotychczasowego k stosujemy refinement i simulated annealing
        if best_overall_k is not None:
            refined_k = refine_candidate_k(best_overall_k)
            candidate_ks.add(refined_k)
            annealed_k = simulated_annealing_k(best_overall_k)
            candidate_ks.add(annealed_k)
        
        for k in candidate_ks:
            ds = []
            for sig in signatures:
                d = recover_d_cached(sig["r"], sig["s"], sig["z"], k)
                if d is not None:
                    ds.append(d)
            if ds:
                error = sum(abs(x - y) for i, x in enumerate(ds) for y in ds[i+1:])
                if error < best_overall_error:
                    best_overall_error = error
                    best_overall_k = k
                    best_overall_ds = ds
                    logging.info(f"Iteracja {iteration}: nowy najlepszy k: {k} z błędem {error}")
                # Sprawdzamy adresy dla każdej odzyskanej d
                for d in ds:
                    p2pkh, bc1, p2sh = generate_addresses_from_private_key(d)
                    print(f"Spróbowano k: {k} | d: {d}", flush=True)
                    print(f"Adres P2PKH: {p2pkh}", flush=True)
                    print(f"Adres Bech32: {bc1}", flush=True)
                    print(f"Adres P2SH: {p2sh}", flush=True)
                    if target_address in (p2pkh, bc1, p2sh):
                        print("🎉 ZNALEZIONO POPRAWNY KLUCZ!", flush=True)
                        print(f"🔑 Klucz prywatny: {d}", flush=True)
                        print(f"🔑 Kandydat k: {k}", flush=True)
                        return d, k
        iteration += 1
        print(f"Iteracja {iteration}: najlepszy dotychczasowy błąd {best_overall_error} dla k {best_overall_k}", flush=True)
    if best_overall_ds:
        print("Końcowy najlepszy kandydat:", flush=True)
        print(f"k: {best_overall_k} | błąd: {best_overall_error} | d: {best_overall_ds}", flush=True)
        return best_overall_ds[0], best_overall_k
    return None, None

# ----------------------------------------------------------------------------
# Główna pętla – skrypt kończy się dopiero po znalezieniu poprawnej pary (d, k)
def main():
    freeze_support()
    target_address = "1612PT2zpMCMRwJsaR9YYs8YPgtYCPKrYe"
    print("==== Rozpoczynam analizę ataków na ECDSA ====", flush=True)
    d_found, k_found = iterative_search(target_address, max_iterations=20000000000)
    if d_found is not None:
        print(f"🔑 Odzyskany klucz prywatny: {d_found}", flush=True)
        print(f"🔑 Kandydat k: {k_found}", flush=True)
    else:
        print("❌ Nie udało się odzyskać klucza prywatnego.", flush=True)

if __name__ == '__main__':
    main()
