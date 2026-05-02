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


def run_fullprove(snarkjs: str, wasm: Path, zkey: Path, input_path: Path,
                  proof_path: Path, public_path: Path) -> None:
    _run([snarkjs, "groth16", "fullprove", str(input_path), str(wasm),
          str(zkey), str(proof_path), str(public_path)])


def run_verify(snarkjs: str, vkey: Path, public_path: Path, proof_path: Path) -> bool:
    res = subprocess.run([snarkjs, "groth16", "verify", str(vkey),
                          str(public_path), str(proof_path)])
    return res.returncode == 0


def build_payload(args: argparse.Namespace) -> bytes:
    snarkjs = _require("snarkjs")
    wasm = Path(args.wasm).resolve()
    zkey = Path(args.zkey).resolve()
    if not wasm.is_file():
        sys.exit(f"error: wasm file not found: {wasm}")
    if not zkey.is_file():
        sys.exit(f"error: zkey file not found: {zkey}")

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

        run_fullprove(snarkjs, wasm, zkey, input_path, proof_path, public_path)

        if args.vkey:
            if not run_verify(snarkjs, Path(args.vkey).resolve(),
                              public_path, proof_path):
                sys.exit("error: snarkjs groth16 verify failed — refusing to emit payload")

        # snarkjs writes JSON; the ZKP1 payload carries it verbatim so
        # that off-box verification ('snarkjs groth16 verify') and on-box
        # verification (rapidsnark, when linked) can both consume it.
        public_bytes = public_path.read_bytes()
        proof_bytes = proof_path.read_bytes()

    return encode_payload(MODE_GROTH16, args.circuit_id, public_bytes, proof_bytes)


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
