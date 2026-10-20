import argparse
import requests
import base64
import json
import os
import sys
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    if log_index < 0:
        raise ValueError("Log index must be a positive integer.")

    url = f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}"
    response = requests.get(url)
    response.raise_for_status()
    
    data = response.json()
    entry_uuid = list(data.keys())[0]
    return data, entry_uuid

def get_verification_proof(log_index, debug=False):
    if log_index < 0:
        raise ValueError("Log index must be a positive integer.")
    
    url = f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}"
    response = requests.get(url)
    response.raise_for_status()
    
    data = response.json()
    entry_uuid = list(data.keys())[0]
    return data[entry_uuid].get('verification', {}).get('inclusionProof', {})

def inclusion(log_index, artifact_filepath, debug=False):
    if not artifact_filepath or not os.path.exists(artifact_filepath):
        print(f"Artifact file not found at {artifact_filepath}")
        return

    data, leaf_hash = get_log_entry(log_index, debug)
    log_entry = data[leaf_hash]

    body_b64 = log_entry['body']
    body_decoded = base64.b64decode(body_b64).decode('utf-8')
    body_json = json.loads(body_decoded)

    sig_b64 = body_json['spec']['signature']['content']
    cert_b64 = body_json['spec']['signature']['publicKey']['content']

    signature = base64.b64decode(sig_b64)
    certificate = base64.b64decode(cert_b64)

    public_key = extract_public_key(certificate)

    # Issue #1 Fix: Halt execution if verification fails
    if not verify_artifact_signature(signature, public_key, artifact_filepath):
        print("Signature verification failed")
        sys.exit(1)

    proof = get_verification_proof(log_index, debug)
    
    tree_size = proof.get('treeSize')
    root_hash = proof.get('rootHash')
    hashes = proof.get('hashes', [])
    index = proof.get('logIndex')

    actual_leaf_hash = compute_leaf_hash(body_b64)
    verify_inclusion(DefaultHasher, index, tree_size, actual_leaf_hash, hashes, root_hash)

    print("Offline verification successful")

def get_latest_checkpoint(debug=False):
    url = "https://rekor.sigstore.dev/api/v1/log"
    response = requests.get(url)
    response.raise_for_status()
    
    checkpoint_data = response.json()
    
    if debug:
        with open('checkpoint.json', 'w') as f:
            json.dump(checkpoint_data, f, indent=4)
            
    return checkpoint_data

def consistency(prev_checkpoint, debug=False):
    if not prev_checkpoint or not prev_checkpoint.get("treeSize"):
        print("Previous checkpoint is invalid or empty.")
        return
    
    latest_checkpoint = get_latest_checkpoint(debug)
    
    # Issue #3 Fix: Compare tree IDs before proceeding
    if prev_checkpoint["treeID"] != latest_checkpoint["treeID"]:
        print("Tree IDs do not match. Checkpoints belong to different trees.")
        sys.exit(1)
        
    first_size = prev_checkpoint["treeSize"]
    last_size = latest_checkpoint["treeSize"]
    
    # Issue #2 Fix: Treat input directly as hex; do not base64 decode
    first_hash = prev_checkpoint["rootHash"]
    if len(first_hash) != 64:
        print("Error: root-hash must be a 64-character hex string.")
        sys.exit(1)
        
    last_hash = latest_checkpoint["rootHash"]
    
    # Issue #4 Fix: Detect fork by checking root hashes if sizes are equal
    if first_size == last_size:
        if first_hash == last_hash:
            print("Log has not grown, checkpoints are identical.")
        else:
            print("Fork detected: Tree sizes are equal but root hashes differ.")
            sys.exit(1)
        return

    # Issue #3 Fix: Add treeID to the Rekor proof URL
    url = f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={first_size}&lastSize={last_size}&treeID={latest_checkpoint['treeID']}"
    response = requests.get(url)
    response.raise_for_status()
    
    proof_data = response.json()
    hashes = proof_data.get('hashes', [])

    verify_consistency(DefaultHasher, first_size, last_size, hashes, first_hash, last_hash)
    
    print("Consistency verification successful")

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode', required=False, action='store_true')
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint from Rekor Server public instance', required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an entry in the Rekor Transparency Log using log index and artifact filename. Usage: --inclusion 126574567', required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying signature', required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given checkpoint with the latest checkpoint.', action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof', required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof', required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof', required=False)
    
    args = parser.parse_args()
    
    if args.debug:
        debug = True
        print("enabled debug mode")
        
    if args.checkpoint:
        checkpoint = get_latest_checkpoint(debug)
        print(json.dumps(checkpoint, indent=4))
        
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
        
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        prev_checkpoint = {
            "treeID": args.tree_id,
            "treeSize": args.tree_size,
            "rootHash": args.root_hash
        }

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()
