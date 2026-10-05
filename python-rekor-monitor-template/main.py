import argparse
import requests
import base64
import json
import os
from util import extract_public_key, verify_artifact_signature
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    # TODO: verify that log index value is sane
    if log_index < 0:
        raise ValueError("Log index must be a positive integer.")

    url = f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}"
    response = requests.get(url)
    response.raise_for_status()
    
    data = response.json()
    entry_uuid = list(data.keys())[0]
    return data, entry_uuid

def get_verification_proof(log_index, debug=False):
    # TODO: verify that log index value is sane
    if log_index < 0:
        raise ValueError("Log index must be a positive integer.")
    
    url = f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}"
    response = requests.get(url)
    response.raise_for_status()
    
    data = response.json()
    entry_uuid = list(data.keys())[0]
    return data[entry_uuid].get('verification', {}).get('inclusionProof', {})

def inclusion(log_index, artifact_filepath, debug=False):
    # TODO::
    # verify that log index and artifact filepath values are sane
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

    # extract_public_key(certificate)
    public_key = extract_public_key(certificate)


    # verify_artifact_signature(signature, public_key, artifact_filepath)
    verify_artifact_signature(signature, public_key, artifact_filepath)

    # get_verification_proof(log_index)
    proof = get_verification_proof(log_index, debug)
    
    tree_size = proof.get('treeSize')
    root_hash = proof.get('rootHash')
    hashes = proof.get('hashes', [])
    index = proof.get('logIndex')

    # verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash)
    actual_leaf_hash = compute_leaf_hash(body_b64)
    verify_inclusion(DefaultHasher, index, tree_size, actual_leaf_hash, hashes, root_hash)

    print("Offline verification successful")

def get_latest_checkpoint(debug=False):
    # TODO: Fetch the latest checkpoint from rekor
    url = "https://rekor.sigstore.dev/api/v1/log"
    response = requests.get(url)
    response.raise_for_status()
    
    checkpoint_data = response.json()
    
    if debug:
        with open('checkpoint.json', 'w') as f:
            json.dump(checkpoint_data, f, indent=4)
            
    return checkpoint_data

def consistency(prev_checkpoint, debug=False):
    # TODO: 
    # verify that prev checkpoint is not empty
    if not prev_checkpoint or not prev_checkpoint.get("treeSize"):
        print("Previous checkpoint is invalid or empty.")
        return
    
    # get_latest_checkpoint()
    latest_checkpoint = get_latest_checkpoint(debug)
    
    first_size = prev_checkpoint["treeSize"]
    last_size = latest_checkpoint["treeSize"]
    
    first_hash = base64.b64decode(prev_checkpoint["rootHash"]).hex()
    last_hash = latest_checkpoint["rootHash"]
    
    if first_size == last_size:
        print("Log has not grown, checkpoints are identical.")
        return

    url = f"https://rekor.sigstore.dev/api/v1/log/proof?firstSize={first_size}&lastSize={last_size}"
    response = requests.get(url)
    response.raise_for_status()
    
    proof_data = response.json()
    hashes = proof_data.get('hashes', [])

    # Pass arguments in the correct order: hasher, size1, size2, proof, root1, root2
    verify_consistency(DefaultHasher, first_size, last_size, hashes, first_hash, last_hash)
    
    # verify_consistency raises an exception if it fails, so if we reach this line, it succeeded
    print("Consistency verification successful")

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
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

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    main()