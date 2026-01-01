import sys
import os
import pickle
import gzip
import argparse
import math

# Try importing optional ML dependencies
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

# Add the vs directory to path so we can import feature extraction if needed, 
# although we will duplicate the simple entropy logic here to keep it standalone.
sys.path.append(os.path.join(os.path.dirname(__file__), 'vs'))

def calculate_entropy(data):
    """
    Calculates the Shannon entropy for the entire data.
    """
    if not data:
        return 0.0
        
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
        
    entropy = 0.0
    total = len(data)
    
    for count in byte_counts:
        if count == 0:
            continue
        p = 1.0 * count / total
        entropy -= p * math.log(p, 256)
        
    return entropy

class SimpleScanner:
    def __init__(self, model_path=None):
        self.model = None
        self.model_path = model_path
        self.load_model()

    def load_model(self):
        if not HAS_NUMPY:
             print("Warning: 'numpy' not found. ML model disabled (running in Heuristic Mode).")
             print("To enable ML, install numpy: pip install numpy")
             return

        if self.model_path and os.path.exists(self.model_path):
            print(f"Loading model from {self.model_path}...")
            try:
                # Try loading with gzip if it ends with .gz
                if self.model_path.endswith('.gz'):
                    with gzip.open(self.model_path, 'rb') as f:
                        self.model = pickle.load(f)
                else:
                    with open(self.model_path, 'rb') as f:
                        self.model = pickle.load(f)
                print("Model loaded successfully.")
            except Exception as e:
                print(f"Warning: Failed to load model: {e}")
                print("Falling back to heuristic mode.")
        else:
             print("No model provider or model file not found. Using heuristic mode.")

    def scan_file(self, file_path):
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} not found.")
            return

        print(f"Scanning {file_path}...")
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            return

        file_size = len(data)
        entropy = calculate_entropy(data)
        
        print(f"Analysis Results:")
        print(f"  File Size: {file_size} bytes")
        print(f"  Entropy:   {entropy:.4f}")
        
        if self.model and HAS_NUMPY:
            # Prepare feature vector: the model likely expects a specific shape
            features = np.array([[entropy, file_size]]) 
            
            try:
                prediction = self.model.predict(features)
                # Some models might support predict_proba, some might not.
                # extra trees usually does.
                if hasattr(self.model, "predict_proba"):
                    prob = self.model.predict_proba(features)
                    confidence = max(prob[0]) * 100
                else:
                    confidence = 100.0 # Binary determination
                
                # Assuming 1 is Malicious, 0 is Benign (common in this dataset)
                is_malicious = prediction[0] == 1
                
                status = "MALICIOUS" if is_malicious else "BENIGN"
                color_code = "\033[91m" if is_malicious else "\033[92m" # Red or Green
                reset_code = "\033[0m"
                
                print(f"  Verdict:   {color_code}{status}{reset_code}")
                print(f"  Confidence: {confidence:.2f}%")
                
            except Exception as e:
                print(f"  Model inference failed: {e}")
                self._heuristic_scan(entropy, file_size)
        else:
            self._heuristic_scan(entropy, file_size)

    def _heuristic_scan(self, entropy, file_size):
        # Simple heuristics if model fails
        # High entropy often means packed or encrypted (suspicious)
        print("  [Using Heuristic Analysis]")

        if entropy > 7.0:
            print("  Verdict:   \033[93mSUSPICIOUS\033[0m")
            print("  Reason:    High entropy detected (> 7.0), indicating packed or encrypted code.")
        elif entropy < 3.0 and file_size > 10000:
             print("  Verdict:   \033[93mSUSPICIOUS\033[0m")
             print("  Reason:    Low entropy for large file, possible text disguise.")
        else:
            print("  Verdict:   \033[92mCLEAN\033[0m")
            print("  Reason:    Entropy levels within normal parameters.")

def main():
    parser = argparse.ArgumentParser(description="Scan a file for potential malware using static analysis.")
    parser.add_argument("file", help="Path to the file to scan")
    parser.add_argument("--model", help="Path to a pickled model file", 
                        default="vs/models/classifier-model-vs264-extratrees-100-entropy.pkl.gz")
    
    args = parser.parse_args()
    
    scanner = SimpleScanner(args.model)
    scanner.scan_file(args.file)

if __name__ == "__main__":
    main()
