#!/usr/bin/env python3
"""Compare classical RSA-3072 with post-quantum ML-KEM-768."""

from __future__ import annotations

import argparse
import os
import statistics
import time
from pathlib import Path

# Prefer a project-local liboqs install when present so the demo runs reliably.
local_oqs = Path(__file__).resolve().parent / ".oqs"
if "OQS_INSTALL_PATH" not in os.environ and (local_oqs / "lib" / "liboqs.dylib").exists():
    os.environ["OQS_INSTALL_PATH"] = str(local_oqs)

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare RSA-3072 and ML-KEM-768 performance and sizes."
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=10,
        help="Number of runs used for median timing (default: 10).",
    )
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be at least 1.")
    return args


def median_rsa_keygen_seconds(runs: int) -> float:
    timings = []
    for _ in range(runs):
        start = time.perf_counter()
        rsa.generate_private_key(public_exponent=65537, key_size=3072)
        timings.append(time.perf_counter() - start)
    return statistics.median(timings)


def median_mlkem_keygen_seconds(runs: int) -> float:
    timings = []
    for _ in range(runs):
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            start = time.perf_counter()
            kem.generate_keypair()
            timings.append(time.perf_counter() - start)
    return statistics.median(timings)


def rsa_sizes() -> tuple[int, int]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    payload = b"post-quantum-poc"
    ciphertext = public_key.encrypt(
        payload,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return len(public_key_bytes), len(ciphertext)


def mlkem_sizes_and_secret_match() -> tuple[int, int, bool]:
    with oqs.KeyEncapsulation("ML-KEM-768") as bob_kem:
        bob_public_key = bob_kem.generate_keypair()

        with oqs.KeyEncapsulation("ML-KEM-768") as alice_kem:
            ciphertext, alice_shared_secret = alice_kem.encap_secret(bob_public_key)

        bob_shared_secret = bob_kem.decap_secret(ciphertext)
        match = alice_shared_secret == bob_shared_secret
        return len(bob_public_key), len(ciphertext), match


def print_results(
    runs: int,
    rsa_median: float,
    mlkem_median: float,
    rsa_public_key_size: int,
    mlkem_public_key_size: int,
    rsa_ciphertext_size: int,
    mlkem_ciphertext_size: int,
    secret_match: bool,
) -> None:
    print("Post-Quantum Proof of Concept")
    print("=" * 34)
    print(f"Timing median ({runs} runs)")
    print(f"- RSA-3072 keygen      : {rsa_median * 1000:.3f} ms")
    print(f"- ML-KEM-768 keygen    : {mlkem_median * 1000:.3f} ms")
    print()
    print("Size comparison (bytes)")
    print(f"- RSA-3072 public key  : {rsa_public_key_size}")
    print(f"- ML-KEM-768 public key: {mlkem_public_key_size}")
    print(f"- RSA-OAEP ciphertext  : {rsa_ciphertext_size}")
    print(f"- ML-KEM ciphertext    : {mlkem_ciphertext_size}")
    print()
    print(f"Shared secret match: {secret_match}")


def main() -> int:
    args = parse_args()

    rsa_median = median_rsa_keygen_seconds(args.runs)
    mlkem_median = median_mlkem_keygen_seconds(args.runs)

    rsa_public_key_size, rsa_ciphertext_size = rsa_sizes()
    mlkem_public_key_size, mlkem_ciphertext_size, secret_match = (
        mlkem_sizes_and_secret_match()
    )

    print_results(
        runs=args.runs,
        rsa_median=rsa_median,
        mlkem_median=mlkem_median,
        rsa_public_key_size=rsa_public_key_size,
        mlkem_public_key_size=mlkem_public_key_size,
        rsa_ciphertext_size=rsa_ciphertext_size,
        mlkem_ciphertext_size=mlkem_ciphertext_size,
        secret_match=secret_match,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
