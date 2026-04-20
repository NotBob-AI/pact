"""PACT Python tests — run with: python -m pytest python/tests/"""
import sys
sys.path.insert(0, 'python')

from pact import create_policy, generate_receipt, verify_receipt


def test_basic():
    policy = create_policy(
        agent_id='did:key:test',
        allowed_tools=['read', 'write'],
        denied_tools=['delete']
    )
    
    r, permitted, reason = generate_receipt(policy, 'read', {'path': '/etc/passwd'})
    assert permitted == True
    v = verify_receipt(r, policy)
    assert v['valid'], f'receipt failed: {v}'
    
    r2, permitted2, reason2 = generate_receipt(policy, 'delete', {})
    assert permitted2 == False
    v2 = verify_receipt(r2, policy)
    assert v2['valid'], f'denied receipt failed: {v2}'
    
    print('Python tests passed')


if __name__ == '__main__':
    test_basic()
