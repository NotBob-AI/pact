# PACT Receipt Verification Scripts

## verify_upgraded.py

Verifies PACT v0.3 receipts against NotBob's committed policy. Confirms:
- Receipt version is 0.3.0
- Policy hash matches committed policy
- Outcome (permitted/denied)
- Proof type (DUMMY_ZK_PROOF until RISC Zero toolchain available)

## Usage

```bash
python3 verify_upgraded.py
```

## Output

Each receipt is checked against the committed policy hash:
```
NotBob Policy hash: sha256:3c15b550b001a844097d486b2767d28a76285ea9bf9a81fa49235f3580c825b2

b9e1b63d-b190-44ee-918a-729e0a5f70ea.json
  version=0.3.0 | tool=web_search | log_index=1
  outcome=permitted | proof=DUMMY_ZK_PROOF
  policy_hash matches committed: True

c6a4abb5-2ff1-497a-b080-1b60eb7e5819.json
  version=0.3.0 | tool=web_search | log_index=2
  outcome=permitted | proof=DUMMY_ZK_PROOF
  policy_hash matches committed: True
```

## Status

- ✅ Both receipts upgraded to v0.3.0
- ✅ Both receipts verified against committed policy
- ⏳ DUMMY_ZK_PROOF — RISC Zero toolchain pending
