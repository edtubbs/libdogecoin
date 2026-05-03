#!/usr/bin/env python3
"""ZK carrier witness/proof helper.

Drives ``snarkjs groth16 fullprove`` for the range-proof circuit (or any
other circuit you point it at), then encodes the resulting (public_inputs,
proof) pair into the canonical ZK carrier payload that libdogecoin's
``such -c zk_add_commit_and_carrier_tx`` consumes.

This is the **only** supported way to produce ZK carrier payloads from
libdogecoin's perspective — proving never runs inside the C library
(see ``include/dogecoin/zk_carrier.h`` and ``src/zk_carrier/zk_groth16.c``).

Usage::

    python3 contrib/zk_carrier/witness_helper.py \\
        --wasm  contrib/zk_carrier/circuits/build/range_proof_js/range_proof.wasm \\
        --zkey  contrib/zk_carrier/circuits/range_proof.zkey \\
        --vkey  contrib/zk_carrier/circuits/verification_key.json \\
        --low   0 --high 1000000 --amount 42000 \\
        --circuit-id 1 \\
        --out-payload payload.hex

Output: ``payload.hex`` is the ASCII-hex of the canonical ZKP1 payload.
Pass it via ``-s`` to ``such -c zk_add_commit_and_carrier_tx``.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence

ZK_MAGIC = b"ZKP1"
MODE_GROTH16 = 0
MODE_PLONK = 1
MODE_GROTH16_BLS12_381 = 3
MODE_PLONK_HALO2_KZG_BN256 = 4
PROOF_SYSTEMS = {
    "groth16": MODE_GROTH16,
    "plonk": MODE_PLONK,
    # Canonical wire layouts that synthesise a deterministic, audit-friendly
    # payload without invoking snarkjs.  Verification is delegated outside
    # libdogecoin (no in-process BLS12-381 / BN256-Halo2 pairing), so the
    # carrier ferries the bytes verbatim — the same byte order that an
    # eventual ZK-verifying opcode adopting these layouts would expect on
    # the script stack (e.g. the DogeOS `OP_CHECKZKP` proposal at
    # dogecoin/dogecoin#3869, or any libdogecoin successor).  See
    # include/dogecoin/zk_carrier.h for the field sizes and rationale.
    "groth16-bls12-381": MODE_GROTH16_BLS12_381,
    "plonk-halo2-kzg-bn256": MODE_PLONK_HALO2_KZG_BN256,
}

# Canonical BLS12-381 Groth16 field sizes — must match the C constants
# DOGECOIN_ZK_BLS12_381_* in include/dogecoin/zk_carrier.h.
BLS12_381_FQ_LEN = 48
BLS12_381_FR_LEN = 32
BLS12_381_PI_A_LEN = BLS12_381_FQ_LEN * 2          # 96
BLS12_381_PI_B_LEN = BLS12_381_FQ_LEN * 4          # 192
BLS12_381_PI_C_LEN = BLS12_381_FQ_LEN * 2          # 96
BLS12_381_VK_CHUNK_LEN = 80
BLS12_381_VK_CHUNKS = 6
BLS12_381_VK_LEN = BLS12_381_VK_CHUNK_LEN * BLS12_381_VK_CHUNKS   # 480
BLS12_381_PROOF_LEN = (BLS12_381_PI_A_LEN + BLS12_381_PI_B_LEN +
                       BLS12_381_PI_C_LEN + BLS12_381_VK_LEN)     # 864
BLS12_381_PUB_LEN = BLS12_381_FR_LEN * 2           # 64

# Canonical BN256 PLONK/Halo2/KZG limits — must match the C constants
# DOGECOIN_ZK_HALO2_BN256_* in include/dogecoin/zk_carrier.h.
HALO2_BN256_FR_LEN = 32
HALO2_BN256_MAX_PROOF = 4096
HALO2_BN256_MAX_VK = 8192
HALO2_BN256_MAX_INPUTS = 64


def _require(tool: str) -> str:
    p = shutil.which(tool)
    if not p:
        sys.exit(f"error: required tool '{tool}' not found on PATH")
    return p


def _run(cmd: Sequence[str]) -> None:
    print("+", " ".join(cmd), file=sys.stderr)
    subprocess.run(list(cmd), check=True)


def encode_payload(mode: int, circuit_id: int,
                   public_inputs: bytes, proof: bytes) -> bytes:
    """Encode the canonical ZKP1 payload (matches dogecoin_zk_encode_payload)."""
    if mode < 0 or mode > 0xFF:
        raise ValueError("mode out of range")
    if len(public_inputs) > 0xFFFF:
        raise ValueError("public_inputs too large (>65535 bytes)")
    if len(proof) > 0x02000000:
        raise ValueError("proof too large (>32 MiB)")
    out = bytearray()
    out += ZK_MAGIC
    out += bytes([mode, 0x00])
    out += struct.pack(">I", circuit_id & 0xFFFFFFFF)
    out += struct.pack(">H", len(public_inputs))
    out += public_inputs
    out += struct.pack(">I", len(proof))
    out += proof
    return bytes(out)


def run_fullprove(snarkjs: str, system: str, wasm: Path, zkey: Path,
                  input_path: Path, proof_path: Path, public_path: Path) -> None:
    _run([snarkjs, system, "fullprove", str(input_path), str(wasm),
          str(zkey), str(proof_path), str(public_path)])


def run_verify(snarkjs: str, system: str, vkey: Path,
               public_path: Path, proof_path: Path) -> bool:
    res = subprocess.run([snarkjs, system, "verify", str(vkey),
                          str(public_path), str(proof_path)])
    return res.returncode == 0


def _kdf_bytes(domain: bytes, n: int) -> bytes:
    """Deterministically derive `n` bytes from a domain-separation tag using
    counter-mode SHA256.  Used to synthesise canonical-layout payloads when
    no real prover is invoked (carrier-only / delegated verification)."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        h = hashlib.sha256()
        h.update(domain)
        h.update(counter.to_bytes(4, "big"))
        out += h.digest()
        counter += 1
    return bytes(out[:n])


def build_canonical_bls12_381_payload(args: argparse.Namespace) -> bytes:
    """Placeholder for DOGECOIN_ZK_MODE_GROTH16_BLS12_381 (=3).

    libdogecoin does not ship a BLS12-381 Groth16 prover (snarkjs is
    BN128-only), so we deliberately refuse to synthesise random bytes
    here — that would only validate the carrier's commit/reveal binding
    on chain, not the proof itself.  Real on-chain validation of mode 3
    requires a real BLS12-381 prover (e.g. arkworks, gnark, or the
    DogeOS reference prover at dogecoin/dogecoin#3869) feeding pre-built
    canonical bytes via --input-json.
    """
    if not args.input_json:
        sys.exit(
            "error: --proof-system groth16-bls12-381 requires --input-json "
            "containing a real BLS12-381 Groth16 proof in the canonical "
            "{pi_a_hex, pi_b_hex, pi_c_hex, vk_hex, public_inputs_hex} "
            "form.  libdogecoin does not embed a BLS12-381 prover; produce "
            "the proof with arkworks / gnark / the DogeOS reference prover "
            "and pass it here.  See doc/zk.md for the field layout."
        )

    spec = json.loads(Path(args.input_json).read_text())
    try:
        pi_a = bytes.fromhex(spec["pi_a_hex"])
        pi_b = bytes.fromhex(spec["pi_b_hex"])
        pi_c = bytes.fromhex(spec["pi_c_hex"])
        vk   = bytes.fromhex(spec["vk_hex"])
        pub_hex_list = spec["public_inputs_hex"]
        pub = b"".join(bytes.fromhex(x) for x in pub_hex_list)
    except (KeyError, ValueError) as exc:
        sys.exit(f"error: malformed --input-json for groth16-bls12-381: {exc}")
    if len(pi_a) != BLS12_381_PI_A_LEN: sys.exit(
        f"error: pi_a must be {BLS12_381_PI_A_LEN} bytes, got {len(pi_a)}")
    if len(pi_b) != BLS12_381_PI_B_LEN: sys.exit(
        f"error: pi_b must be {BLS12_381_PI_B_LEN} bytes, got {len(pi_b)}")
    if len(pi_c) != BLS12_381_PI_C_LEN: sys.exit(
        f"error: pi_c must be {BLS12_381_PI_C_LEN} bytes, got {len(pi_c)}")
    if len(vk)   != BLS12_381_VK_LEN:   sys.exit(
        f"error: vk must be {BLS12_381_VK_LEN} bytes, got {len(vk)}")
    if len(pub)  != BLS12_381_PUB_LEN:  sys.exit(
        f"error: public_inputs must total {BLS12_381_PUB_LEN} bytes, got {len(pub)}")

    proof = pi_a + pi_b + pi_c + vk

    if args.save_proof:
        Path(args.save_proof).write_text(json.dumps({
            "proof_system": "groth16-bls12-381",
            "carrier_mode": MODE_GROTH16_BLS12_381,
            "circuit_id": args.circuit_id,
            "pi_a_hex": pi_a.hex(),
            "pi_b_hex": pi_b.hex(),
            "pi_c_hex": pi_c.hex(),
            "vk_hex":   vk.hex(),
            "vk_chunks_hex": [vk[i*BLS12_381_VK_CHUNK_LEN:
                                 (i+1)*BLS12_381_VK_CHUNK_LEN].hex()
                              for i in range(BLS12_381_VK_CHUNKS)],
            "verification": "delegated (BLS12-381 pairing not in libdogecoin)",
        }, indent=2) + "\n")
    if args.save_public:
        Path(args.save_public).write_text(json.dumps({
            "proof_system": "groth16-bls12-381",
            "public_inputs_hex": [p.hex() for p in
                                  [pub[i*BLS12_381_FR_LEN:
                                       (i+1)*BLS12_381_FR_LEN]
                                   for i in range(2)]],
        }, indent=2) + "\n")

    return encode_payload(MODE_GROTH16_BLS12_381, args.circuit_id, pub, proof)


def build_canonical_plonk_halo2_bn256_payload(args: argparse.Namespace) -> bytes:
    """Placeholder for DOGECOIN_ZK_MODE_PLONK_HALO2_KZG_BN256 (=4).
    Same rationale as build_canonical_bls12_381_payload above:
    libdogecoin does not ship an openvm/Halo2-KZG prover, so we refuse
    to fabricate proof bytes — operators must supply a real proof via
    --input-json containing {proof_hex, vk_hex, public_inputs_hex}.
    """
    if not args.input_json:
        sys.exit(
            "error: --proof-system plonk-halo2-kzg-bn256 requires "
            "--input-json with a real Halo2/KZG/BN256 proof in the "
            "canonical {proof_hex, vk_hex, public_inputs_hex} form.  "
            "libdogecoin does not embed a Halo2 prover; produce the "
            "proof with openvm / halo2-snark or the DogeOS reference "
            "prover and pass it here."
        )

    spec = json.loads(Path(args.input_json).read_text())
    try:
        proof = bytes.fromhex(spec["proof_hex"])
        vk    = bytes.fromhex(spec["vk_hex"])
        pub_hex_list = spec["public_inputs_hex"]
        pub_concat = b"".join(bytes.fromhex(x) for x in pub_hex_list)
        n_pub = len(pub_hex_list)
    except (KeyError, ValueError) as exc:
        sys.exit(f"error: malformed --input-json for plonk-halo2-kzg-bn256: {exc}")
    if len(proof) > HALO2_BN256_MAX_PROOF: sys.exit(
        f"error: proof_hex exceeds {HALO2_BN256_MAX_PROOF} bytes")
    if len(vk)    > HALO2_BN256_MAX_VK:    sys.exit(
        f"error: vk_hex exceeds {HALO2_BN256_MAX_VK} bytes")
    if n_pub      > HALO2_BN256_MAX_INPUTS: sys.exit(
        f"error: more than {HALO2_BN256_MAX_INPUTS} public inputs")
    for h in pub_hex_list:
        if len(bytes.fromhex(h)) != HALO2_BN256_FR_LEN:
            sys.exit(f"error: each public input must be {HALO2_BN256_FR_LEN} bytes")

    pub_field   = struct.pack(">H", n_pub) + pub_concat
    proof_field = (struct.pack("<I", len(proof)) + proof +
                   struct.pack("<I", len(vk))    + vk)

    if args.save_proof:
        Path(args.save_proof).write_text(json.dumps({
            "proof_system": "plonk-halo2-kzg-bn256",
            "carrier_mode": MODE_PLONK_HALO2_KZG_BN256,
            "circuit_id": args.circuit_id,
            "proof_len": len(proof), "proof_hex": proof.hex(),
            "vk_len":    len(vk),    "vk_hex":    vk.hex(),
            "verification": "delegated (BN256/Halo2 verifier not in libdogecoin)",
        }, indent=2) + "\n")
    if args.save_public:
        Path(args.save_public).write_text(json.dumps({
            "proof_system": "plonk-halo2-kzg-bn256",
            "n_public_inputs": n_pub,
            "public_inputs_hex": pub_hex_list,
        }, indent=2) + "\n")

    return encode_payload(MODE_PLONK_HALO2_KZG_BN256, args.circuit_id,
                          pub_field, proof_field)


def build_payload(args: argparse.Namespace) -> bytes:
    system = args.proof_system
    if system not in PROOF_SYSTEMS:
        sys.exit(f"error: unsupported --proof-system {system!r} "
                 f"(choose: {', '.join(PROOF_SYSTEMS)})")
    if system == "groth16-bls12-381":
        return build_canonical_bls12_381_payload(args)
    if system == "plonk-halo2-kzg-bn256":
        return build_canonical_plonk_halo2_bn256_payload(args)

    snarkjs = _require("snarkjs")
    wasm = Path(args.wasm).resolve()
    zkey = Path(args.zkey).resolve()
    if not wasm.is_file():
        sys.exit(f"error: wasm file not found: {wasm}")
    if not zkey.is_file():
        sys.exit(f"error: zkey file not found: {zkey}")

    mode = PROOF_SYSTEMS[system]

    with tempfile.TemporaryDirectory(prefix="zkc_") as td:
        td_p = Path(td)
        input_path = td_p / "input.json"
        proof_path = td_p / "proof.json"
        public_path = td_p / "public.json"
        # Range-proof witness format (matches range_proof.circom).
        # If you wire a different circuit, override --input-json with the
        # exact JSON that circuit expects.
        if args.input_json:
            input_path.write_text(Path(args.input_json).read_text())
        else:
            input_path.write_text(json.dumps({
                "low": str(args.low),
                "high": str(args.high),
                "amount": str(args.amount),
            }))

        run_fullprove(snarkjs, system, wasm, zkey, input_path, proof_path, public_path)

        if args.vkey:
            if not run_verify(snarkjs, system, Path(args.vkey).resolve(),
                              public_path, proof_path):
                sys.exit(f"error: snarkjs {system} verify failed — refusing to emit payload")

        # snarkjs writes JSON; the ZKP1 payload carries it verbatim so
        # that off-box verification ('snarkjs <system> verify') and on-box
        # verification (rapidsnark, when linked) can both consume it.
        public_bytes = public_path.read_bytes()
        proof_bytes = proof_path.read_bytes()

        # Persist the raw snarkjs proof.json / public.json next to the
        # caller's --out-payload (when --save-proof/--save-public are
        # provided) so the post-spvnode external verifier
        # (`snarkjs <system> verify`) in broadcast_set.sh can be invoked
        # end-to-end against the very same artefacts that were embedded
        # in the on-chain ZKP1 payload.
        if args.save_proof:
            Path(args.save_proof).write_bytes(proof_bytes)
        if args.save_public:
            Path(args.save_public).write_bytes(public_bytes)

    return encode_payload(mode, args.circuit_id, public_bytes, proof_bytes)


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--wasm", required=True, help="path to circuit .wasm")
    p.add_argument("--zkey", required=True, help="path to circuit .zkey (Groth16 proving key)")
    p.add_argument("--vkey", help="path to verification_key.json (optional sanity check)")
    p.add_argument("--circuit-id", type=lambda x: int(x, 0), default=1,
                   help="application-defined 32-bit circuit identifier (default: 1)")
    p.add_argument("--low", type=int, help="public lower bound (range proof)")
    p.add_argument("--high", type=int, help="public upper bound (range proof)")
    p.add_argument("--amount", type=int, help="private witness amount (range proof)")
    p.add_argument("--input-json", help="optional path to a circuit-specific input.json "
                                        "(overrides --low/--high/--amount)")
    p.add_argument("--proof-system", default="groth16",
                   choices=sorted(PROOF_SYSTEMS.keys()),
                   help="proving system used by snarkjs fullprove/verify "
                        "(default: groth16, also: plonk → ZKP1 mode byte 1)")
    p.add_argument("--save-proof", help="optional path to copy the raw snarkjs proof.json "
                                        "(used by broadcast_set.sh's post-spvnode "
                                        "external verifier)")
    p.add_argument("--save-public", help="optional path to copy the raw snarkjs public.json "
                                         "(used by broadcast_set.sh's post-spvnode "
                                         "external verifier)")
    p.add_argument("--out-payload", required=True,
                   help="where to write the hex-encoded ZKP1 payload")
    args = p.parse_args(argv)

    if not args.input_json and (args.low is None or args.high is None or args.amount is None):
        p.error("either --input-json or --low/--high/--amount must be provided")

    payload = build_payload(args)
    Path(args.out_payload).write_text(payload.hex())
    print(f"wrote {len(payload)}-byte ZKP1 payload to {args.out_payload}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
