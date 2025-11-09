# ECDSA multi-technique key-recovery pipeline — English description

This Python script is an experimental, multi-method toolkit that attempts to **recover an ECDSA private key (`d`)** by searching for plausible nonces (`k`) that make many observed signatures consistent with a single private key.  
It combines deterministic algebra, ML prediction, metaheuristics (genetic algorithm, simulated annealing), brute-force refinement and auxiliary utilities (address generation, address decoding). The script is intended **only for research / educational** exploration of ECDSA weaknesses (e.g., poor nonce generation). Do **not** use it to attack systems you don't own or have permission to test.

---

## Quick features summary

- Loads a fixed dataset of real-looking ECDSA signatures (`r`, `s`, `z`) for secp256k1.
- Tries to recover `d` using candidate `k` values and the formula `d = ((s*k - z) * r^{-1}) mod n`.
- Caches `d` recovery to speed repeated calculations.
- Uses an ML regressor (XGBoost) to predict likely nonces from extracted signature features.
- Uses a Genetic Algorithm (DEAP) to search for good `k`.
- Uses Simulated Annealing and local brute-force refinement to polish candidate `k`.
- Placeholder for a lattice attack (you can replace the placeholder with a real implementation).
- Generates Bitcoin addresses from recovered private keys (P2PKH, Bech32, nested P2SH) and compares them to a target address.
- Iterative outer loop combining all candidate sources until a match for a target address is found or iterations are exhausted.
- Logging of candidate evaluations to `optimization.log`.

---

## High-level flow / important functions

### `get_hash160_from_address(addr)`
- Decodes a Bitcoin address (legacy Base58 P2PKH/P2SH or Bech32) and returns the underlying `hash160` hex to compare generated addresses with the target.

### `get_real_transactions()`
- Returns the hard-coded list of observed transactions/signatures. Each signature is a dict with hexadecimal `r`, `s`, `z` parsed to integers.

### `recover_d_cached(r, s, z, k)`
- Cached function (via `lru_cache`) that computes `d = ((s*k - z) * r^{-1}) mod n` when `r` invertible.
- Returns `None` if the modular inverse fails or the result is out of range.

### `objective(k)`
- For a candidate `k`, computes candidate `d` for each signature.
- Returns an error measure that is sum of absolute pairwise differences between candidate `d` values (smaller is better).
- Used by search procedures as the objective to minimize.

### ML model: `extract_features`, `train_ml_model`, `predict_k_with_ml`
- `extract_features(signatures)` converts signature tuples into normalized numeric features (ratios, logs, deltas).
- `train_ml_model(signatures)` trains an `xgboost.XGBRegressor` on those features to predict `k/n` (synthetic `y` in script).
- `predict_k_with_ml(model, signatures)` returns predicted integer `k` candidates for each signature.
- Note: current script uses random `y` for training (placeholder). To be useful, you must supply labelled historical `k` values or a proper training pipeline.

### Genetic algorithm: `genetic_algorithm_k`
- Uses DEAP to evolve integer `k` values and minimize the objective.
- Returns the best `k` found.

### Simulated annealing: `simulated_annealing_k`
- Local optimization that allows uphill moves with a temperature schedule to escape local minima.

### `refine_candidate_k(candidate_k, search_range)`
- Simple local brute-force search around `candidate_k` to find immediate improvements.

### `lattice_attack(signatures)`
- Placeholder. Replace this with a lattice-based nonce-reuse or bias attack if you have weak nonces and an appropriate lattice solver.

### `generate_addresses_from_private_key(d)`
- Converts recovered `d` to compressed public key, computes `hash160` and returns:
  - P2PKH (legacy) address
  - Bech32 (native segwit) address
  - nested P2SH (P2WPKH-in-P2SH) address
- Uses `ecdsa` and standard hashing (SHA256 → RIPEMD160) and Base58/Bech32 encoding.

### `iterative_search(target_address, max_iterations)`
- The outer orchestration:
  - Trains ML model and gets ML-predicted `k`s.
  - Runs genetic algorithm and lattice placeholder.
  - Optionally refines best-known candidate with refinement + simulated annealing.
  - For each candidate `k`, recovers `d` values for all signatures and checks address matches.
  - Logs progress to `optimization.log` and prints progress to stdout.
  - Stops when a generated address matches the `target_address` or when iteration limit is reached.

---

## How to run (environment & pip)

Recommended: create and activate a virtual environment.

```bash
python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows
venv\Scripts\activate
nstall required packages:

pip install ecdsa base58 bech32 sympy numpy xgboost deap


Notes:

xgboost can require a C++ build toolchain; on many systems pip install xgboost works, otherwise use a prebuilt wheel or your OS package manager.

bech32 package name may vary; one common pip package is bech32 or segwit_addr. If pip cannot find bech32, search for a compatible Bech32 encoder/decoder or substitute your own.

deap is the Genetic Algorithm library used for the GA portion.

Run:

python your_script_name.py


The script writes progress to optimization.log and prints iterations and candidate addresses to the console.

Configuration points you will likely want to change

Replace the placeholder ML training labels with real k training data (if you have it). As written, the ML model uses random labels and will not produce meaningful k.

Implement a real lattice_attack() function if you expect correlated or partially-known nonces (typical lattice attacks require many signatures and specialized matrix construction).

Tweak genetic algorithm parameters (generations, population_size) and simulated annealing (T_init, alpha, iterations) to suit available compute/time.

Improve the objective function: the script currently uses absolute differences between candidate ds. You may want more robust scoring (e.g., penalize invalid d, incorporate address-check failures, or use a normalized variance).

Make sure the target_address is correct and that the address decoding function supports the exact address formats you need.

Outputs & artifacts

Console output — iteration logs and attempted addresses.

optimization.log — CSV-like logging lines with candidates, errors and recovered ds.

If a match is found, the function returns (d, k) and prints the recovered private key and candidate k.

Important legal / ethical disclaimer

This tool is an academic/proof-of-concept demonstration of how weak or leaked nonces can lead to private-key recovery. Using this script to recover keys you do not own or to access systems without explicit authorization is unethical and illegal in most jurisdictions. Only run tests on keys/accounts you own or on systems where you have explicit permission.

Minimal file layout suggestion
ecdsa_recovery/
├─ recover.py         # this script
├─ requirements.txt   # list of dependencies
└─ optimization.log   # created at runtime

Suggested next steps (if you want to develop further)

Replace placeholders with real training labels or use simulated signature data with known k values to train ML models properly.

Implement a lattice-based nonce-reuse attack (e.g., using fplll or sage for lattice reduction) if you suspect correlated nonces.

Add checkpoints and resume capability for long runs.

Parallelize candidate evaluation for speed (careful with lru_cache and process boundaries).

Add deterministic unit tests with synthetic signatures to validate each module.

License

Use under an appropriate license for research/educational code (e.g., MIT) and include the legal disclaimer in the repository README.

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
