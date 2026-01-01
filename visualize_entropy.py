import sys
import os
import math
import argparse

try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

def calculate_local_entropy(data, window_size=256):
    """
    Calculates the Shannon entropy for a sliding window or chunks of the data.
    """
    entropies = []
    if len(data) < window_size:
        return [0]
    
    for i in range(0, len(data), window_size):
        chunk = data[i:i+window_size]
        if not chunk:
            break
        
        # Calculate entropy for this chunk
        byte_counts = [0] * 256
        for byte in chunk:
            byte_counts[byte] += 1
            
        entropy = 0.0
        length = len(chunk)
        
        for count in byte_counts:
            if count == 0:
                continue
            p = 1.0 * count / length
            entropy -= p * math.log(p, 256)
            
        entropies.append(entropy)
        
    return entropies

def visualize_file(file_path, output_image):
    if not HAS_MATPLOTLIB:
        print("Error: 'matplotlib' not found. Cannot generate entropy graph.")
        print("To enable visualization, install matplotlib: pip install matplotlib")
        return

    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return

    print(f"Reading {file_path}...")
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    print(f"Calculating entropy (Size: {len(data)} bytes)...")
    entropies = calculate_local_entropy(data, window_size=256)

    plt.figure(figsize=(12, 6))
    plt.plot(entropies, color='blue', linewidth=0.5)
    plt.title(f'Entropy Visualization: {os.path.basename(file_path)}')
    plt.xlabel('Block Index (256 bytes per block)')
    plt.ylabel('Entropy (0.0 - 1.0)')
    plt.ylim(0, 1.0)
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    
    # Shade high entropy areas which might be packed/encrypted
    # plt.fill_between(range(len(entropies)), entropies, color='blue', alpha=0.1)

    print(f"Saving plot to {output_image}...")
    plt.savefig(output_image)
    print("Done.")

def main():
    parser = argparse.ArgumentParser(description="Visualize the entropy of a file to detect packed/encrypted sections.")
    parser.add_argument("file", help="Path to the file to scan")
    parser.add_argument("-o", "--output", help="Output image path", default="entropy_plot.png")
    
    args = parser.parse_args()
    
    visualize_file(args.file, args.output)

if __name__ == "__main__":
    main()
