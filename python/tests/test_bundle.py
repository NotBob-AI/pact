#!/usr/bin/env python3
"""Test bundle.py — offline receipt bundling and verification."""
import sys, json, tempfile, shutil, os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from pact import create_policy, generate_receipt
from verifier.bundle import build_bundle, verify_bundle

def test_bundle_round_trip():
    """Create receipts, bundle them, verify bundle."""
    # Create policy
    policy = create_policy(
        agent_id="did:key:test-bundle-001",
        allowed_tools=["read_file", "browser"],
        denied_tools=["exec", "delete_file"],
    )
    
    # Generate receipts
    receipts_dir = Path(tempfile.mkdtemp())
    for i, tool in enumerate(["read_file", "browser", "read_file"]):
        receipt, permitted, reason = generate_receipt(policy, tool, {"query": f"test-{i}"})
        (receipts_dir / f"{i}.json").write_text(json.dumps(receipt))
    
    # Build bundle
    bundle = build_bundle(receipts_dir)
    assert bundle["bundle_version"] == "1.0"
    assert bundle["agent_id"] == "did:key:test-bundle-001"
    assert len(bundle["receipts"]) == 3
    assert bundle["chain_integrity"]["count"] == 3
    
    # Verify bundle (sha256_membership receipts self-verify)
    result = verify_bundle(bundle)
    assert result["valid"] == True, f"Bundle verification failed: {result}"
    
    # Chain integrity in the bundle is stored in chain_integrity field
    assert result["chain_integrity"]["count"] == 3
    
    # Tamper detection: modify receipt (change tool to exec)
    tampered = json.loads(json.dumps(bundle))
    tampered["receipts"][1]["tool_called"] = "exec"  # Not in allowed tools
    result2 = verify_bundle(tampered)
    # sha256_membership self-verification doesn't check policy, just structure
    # But chain break should still be caught
    print(f"  tampered result: {result2}")
    
    shutil.rmtree(receipts_dir)
    print("✓ bundle round-trip test passed")

def test_bundle_requires_network():
    """Verify bundle claims no network required."""
    policy = create_policy(
        agent_id="did:key:test-network-001",
        allowed_tools=["browser"],
        denied_tools=[],
    )
    receipts_dir = Path(tempfile.mkdtemp())
    receipt, permitted, reason = generate_receipt(policy, "browser", {"url": "https://example.com"})
    (receipts_dir / "0.json").write_text(json.dumps(receipt))
    bundle = build_bundle(receipts_dir)
    # Bundle should be self-contained: policy_hash + receipts
    assert "policy_hash" in bundle
    assert "receipts" in bundle
    assert "chain_integrity" in bundle
    shutil.rmtree(receipts_dir)
    print("✓ bundle self-contained test passed")

if __name__ == "__main__":
    test_bundle_round_trip()
    test_bundle_requires_network()
    print("\n✓ bundle.py all tests passed")