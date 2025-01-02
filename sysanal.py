import hashlib
import json
import os

def load_signatures(file_path):
    """Load malware signatures from a JSON file."""
    print("Loading malware signatures...")
    with open(file_path, 'r') as file:
        data = json.load(file)
    print("Signatures loaded.")
    return data.get("signatures", [])

def compute_hash(file_path, hash_algorithm="md5"):
    """Compute the hash of a file."""
    try:
        with open(file_path, 'rb') as file:
            if hash_algorithm == "md5":
                hasher = hashlib.md5()
            else:
                hasher = hashlib.sha256()

            while chunk := file.read(8192):
                hasher.update(chunk)
            return hasher.hexdigest()
    except Exception as e:
        return None

def scan_directory(directory, malware_signatures):
    """Scan a directory and return a list of malicious files."""
    malicious_files = []
    total_files = sum(len(files) for _, _, files in os.walk(directory))  # Count total files
    scanned_files = 0

    print(f"Total files to scan: {total_files}")

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = compute_hash(file_path, hash_algorithm="md5")  # Use MD5 for now
            if file_hash in malware_signatures:
                malicious_files.append(file_path)

            scanned_files += 1
            print_progress(scanned_files, total_files)

    print(f"\nScan Complete! Malicious files found: {len(malicious_files)}")
    return malicious_files

def print_progress(current, total):
    """Display a progress bar in the terminal."""
    progress = (current / total) * 100
    print(f"\rProgress: {progress:.3f}% Completed", end="")

if __name__ == "__main__":
    print("Starting malware scan...")

    # Load signatures from hashes.json (adjust path as necessary)
    signatures = load_signatures("hashes.json")
    
    # Specify the directory to scan (adjust path to your Downloads folder)
    results = scan_directory("C:\\", signatures)
    
    
    print(f"Malicious files found: {len(results)}")
    for file in results:
        print(f"Malicious: {file}")
