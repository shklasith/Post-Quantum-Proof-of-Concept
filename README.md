# Post-Quantum Proof of Concept (Python)

This project compares classical `RSA-3072` with post-quantum `ML-KEM-768` and demonstrates key encapsulation/decapsulation with matching shared secrets.

## Prerequisite: liboqs system library

`liboqs-python` needs the Open Quantum Safe C library available on your machine.

- macOS (Homebrew): `brew install liboqs` (installs static library only)
- Linux: build/install from [Open Quantum Safe liboqs](https://github.com/open-quantum-safe/liboqs)

For this PoC, a shared library (`liboqs.dylib`/`.so`) is required. If your system package does not provide it, build locally:

```bash
brew install cmake
git clone --depth 1 https://github.com/open-quantum-safe/liboqs .build/liboqs-src
cmake -S .build/liboqs-src -B .build/liboqs-src/build \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_INSTALL_PREFIX="$PWD/.oqs"
cmake --build .build/liboqs-src/build --parallel 4
cmake --build .build/liboqs-src/build --target install
```

The script auto-detects a local install at `.oqs` via `OQS_INSTALL_PATH`.

## Setup (venv first)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run

Default run count is 10 median timing samples:

```bash
python pqc_compare.py
```

Custom run count:

```bash
python pqc_compare.py --runs 20
```

## Output

The script prints:

- Median key generation time (`RSA-3072` vs `ML-KEM-768`)
- Public key size comparison (bytes)
- Ciphertext size comparison (RSA-OAEP vs ML-KEM encapsulation)
- Shared secret verification result (`True` when Alice/Bob secrets match)
