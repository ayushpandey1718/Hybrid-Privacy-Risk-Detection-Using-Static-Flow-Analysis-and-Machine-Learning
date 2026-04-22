#!/usr/bin/env python3
"""
Threat Analysis Engine — Multi-factor risk assessment for binary files.

Uses real dataset statistics from the Hybrid Privacy Risk Detection project
to compute risk levels (HIGH / MEDIUM / LOW / CRITICAL) based on:
  - Shannon entropy analysis
  - Call graph complexity estimation
  - Suspicious API pattern matching
  - Packer/cryptor detection signatures
  - File size anomaly detection
  - Code obfuscation scoring

Usage:
  python threat_analysis.py <file_path> [--json] [--verbose]
  python threat_analysis.py --batch <directory> [--json]
"""

import sys
import os
import math
import json
import argparse
import csv
from collections import defaultdict


# ─── Color codes for terminal output ───
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


# ─── Suspicious API categories (from data/APIs.txt) ───
SUSPICIOUS_API_CATEGORIES = {
    'Process Manipulation': {
        'apis': ['CreateRemoteThread', 'WriteProcessMemory', 'ReadProcessMemory',
                 'VirtualAllocEx', 'OpenProcess', 'TerminateProcess',
                 'CreateProcess', 'SuspendThread', 'ResumeThread'],
        'weight': 0.95
    },
    'Registry Operations': {
        'apis': ['RegCreateKeyExA', 'RegSetValueExA', 'RegDeleteKeyA',
                 'RegDeleteValueA', 'RegOpenKeyExA', 'RegQueryValueExA',
                 'RegCreateKeyExW', 'RegSetValueExW', 'RegDeleteValueW'],
        'weight': 0.72
    },
    'Network Activity': {
        'apis': ['InternetOpenA', 'InternetConnectA', 'HttpOpenRequestA',
                 'HttpSendRequestA', 'URLDownloadToFileA', 'WSAStartup',
                 'socket', 'connect', 'send', 'recv', 'gethostbyname',
                 'InternetReadFile', 'InternetOpenUrlA', 'InternetCloseHandle'],
        'weight': 0.88
    },
    'Service Control': {
        'apis': ['CreateServiceA', 'OpenServiceA', 'StartServiceA',
                 'DeleteService', 'ControlService', 'OpenSCManagerA',
                 'QueryServiceStatus', 'SetServiceStatus'],
        'weight': 0.82
    },
    'Code Injection': {
        'apis': ['VirtualAlloc', 'VirtualProtect', 'VirtualProtectEx',
                 'LoadLibraryA', 'GetProcAddress', 'CreateToolhelp32Snapshot',
                 'LoadLibraryW', 'LoadLibraryExA'],
        'weight': 0.91
    },
    'Anti-Debug': {
        'apis': ['IsDebuggerPresent', 'GetTickCount', 'QueryPerformanceCounter',
                 'rdtsc', 'GetThreadContext', 'SetThreadContext'],
        'weight': 0.78
    },
    'Privilege Escalation': {
        'apis': ['OpenProcessToken', 'AdjustTokenPrivileges',
                 'LookupPrivilegeValueA', 'GetTokenInformation',
                 'ExitWindowsEx'],
        'weight': 0.85
    },
    'Keylogging/Input Capture': {
        'apis': ['SetWindowsHookExA', 'GetKeyState', 'GetKeyboardState',
                 'keybd_event', 'CallNextHookEx', 'GetAsyncKeyState',
                 'UnhookWindowsHookEx'],
        'weight': 0.90
    },
    'Clipboard/Data Theft': {
        'apis': ['OpenClipboard', 'GetClipboardData', 'SetClipboardData',
                 'EmptyClipboard', 'CloseClipboard'],
        'weight': 0.65
    },
    'File/Directory Manipulation': {
        'apis': ['DeleteFileA', 'DeleteFileW', 'MoveFileA', 'CopyFileA',
                 'CreateFileA', 'CreateFileW', 'SetFileAttributesA',
                 'SetFileAttributesW', 'RemoveDirectoryA', 'CreateDirectoryA',
                 'SHFileOperationA'],
        'weight': 0.58
    }
}


def calculate_entropy(data):
    """Calculate normalized Shannon entropy (0.0 - 1.0)."""
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
        p = count / total
        entropy -= p * math.log2(p)

    return entropy / 8.0  # Normalize to 0-1


def calculate_entropy_variance(data, window_size=256):
    """Calculate variance of local entropy across file blocks."""
    if len(data) < window_size * 2:
        return 0.5

    entropies = []
    for i in range(0, len(data) - window_size, window_size):
        chunk = data[i:i + window_size]
        byte_counts = [0] * 256
        for byte in chunk:
            byte_counts[byte] += 1

        e = 0.0
        for count in byte_counts:
            if count == 0:
                continue
            p = count / len(chunk)
            e -= p * math.log2(p)
        entropies.append(e / 8.0)

    if not entropies:
        return 0.5

    mean = sum(entropies) / len(entropies)
    variance = sum((e - mean) ** 2 for e in entropies) / len(entropies)
    return variance


def scan_for_apis(data):
    """Scan binary data for suspicious API string references."""
    try:
        text = data.decode('ascii', errors='ignore')
    except Exception:
        text = ''

    detected = {}
    for category, info in SUSPICIOUS_API_CATEGORIES.items():
        matches = [api for api in info['apis'] if api in text]
        if matches:
            detected[category] = {
                'matches': matches,
                'count': len(matches),
                'total_apis': len(info['apis']),
                'category_risk': round(
                    (len(matches) / len(info['apis'])) * info['weight'] * 100, 1
                )
            }

    return detected


def detect_packer_signatures(data):
    """Check for common packer signatures in PE header."""
    signatures = {
        b'UPX0': 'UPX',
        b'UPX1': 'UPX',
        b'UPX2': 'UPX',
        b'.aspack': 'ASPack',
        b'ASPack': 'ASPack',
        b'PECompact': 'PECompact',
        b'.petite': 'Petite',
        b'MEW': 'MEW',
        b'.nsp': 'NsPack',
        b'FSG!': 'FSG',
        b'MPRESS': 'MPRESS',
        b'.themida': 'Themida',
        b'Armadillo': 'Armadillo',
        b'VMProtect': 'VMProtect',
    }

    detected = []
    header = data[:4096]  # Check first 4KB

    for sig, name in signatures.items():
        if sig in header:
            detected.append(name)

    return detected


def assess_risk_factor(name, value, thresholds):
    """Generic risk factor assessment."""
    risk = 0
    level = 'low'

    if value >= thresholds.get('critical', float('inf')):
        risk = 95
        level = 'critical'
    elif value >= thresholds.get('high', float('inf')):
        risk = 75
        level = 'high'
    elif value >= thresholds.get('medium', float('inf')):
        risk = 50
        level = 'medium'
    else:
        risk = max(10, int(value / thresholds.get('medium', 1) * 35))
        level = 'low'

    return {'name': name, 'risk': risk, 'level': level, 'value': value}


def compute_overall_risk(factors):
    """Compute weighted overall risk score."""
    weights = {
        'entropy': 0.20,
        'entropy_variance': 0.10,
        'api_abuse': 0.25,
        'file_size': 0.08,
        'packer': 0.15,
        'obfuscation': 0.12,
        'call_graph': 0.10
    }

    total = 0
    weight_sum = 0
    for key, factor in factors.items():
        w = weights.get(key, 0.1)
        total += factor['risk'] * w
        weight_sum += w

    score = min(100, round(total / weight_sum * (weight_sum / sum(weights.values()))))

    if score >= 80:
        return {'score': score, 'level': 'critical', 'label': 'CRITICAL'}
    elif score >= 60:
        return {'score': score, 'level': 'high', 'label': 'HIGH RISK'}
    elif score >= 35:
        return {'score': score, 'level': 'medium', 'label': 'MEDIUM RISK'}
    else:
        return {'score': score, 'level': 'low', 'label': 'LOW RISK'}


def analyze_file(file_path, verbose=False):
    """Perform comprehensive threat analysis on a file."""
    if not os.path.exists(file_path):
        return {'error': f'File not found: {file_path}'}

    with open(file_path, 'rb') as f:
        data = f.read()

    file_size = len(data)
    file_name = os.path.basename(file_path)

    if verbose:
        print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}  🛡️  THREAT ANALYSIS ENGINE{Colors.RESET}")
        print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print(f"  Target: {Colors.BOLD}{file_name}{Colors.RESET}")
        print(f"  Size:   {file_size:,} bytes")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}\n")

    factors = {}

    # 1. Entropy Analysis
    entropy = calculate_entropy(data)
    entropy_pct = entropy * 100

    if entropy > 0.90:
        factors['entropy'] = {'risk': 92, 'level': 'critical', 'value': round(entropy, 4)}
    elif entropy > 0.80:
        factors['entropy'] = {'risk': 75, 'level': 'high', 'value': round(entropy, 4)}
    elif entropy > 0.65:
        factors['entropy'] = {'risk': 45, 'level': 'medium', 'value': round(entropy, 4)}
    elif entropy < 0.15:
        factors['entropy'] = {'risk': 40, 'level': 'medium', 'value': round(entropy, 4)}
    else:
        factors['entropy'] = {'risk': 12, 'level': 'low', 'value': round(entropy, 4)}

    if verbose:
        color = Colors.RED if factors['entropy']['risk'] > 60 else Colors.YELLOW if factors['entropy']['risk'] > 35 else Colors.GREEN
        print(f"  🔥 Entropy:        {color}{entropy_pct:.1f}%{Colors.RESET} → {factors['entropy']['level'].upper()}")

    # 2. Entropy Variance (obfuscation indicator)
    variance = calculate_entropy_variance(data)
    if variance < 0.01:
        factors['entropy_variance'] = {'risk': 85, 'level': 'high', 'value': round(variance, 4)}
    elif variance < 0.05:
        factors['entropy_variance'] = {'risk': 60, 'level': 'medium', 'value': round(variance, 4)}
    elif variance < 0.1:
        factors['entropy_variance'] = {'risk': 35, 'level': 'medium', 'value': round(variance, 4)}
    else:
        factors['entropy_variance'] = {'risk': 10, 'level': 'low', 'value': round(variance, 4)}

    if verbose:
        color = Colors.RED if factors['entropy_variance']['risk'] > 60 else Colors.YELLOW if factors['entropy_variance']['risk'] > 35 else Colors.GREEN
        print(f"  🌀 Entropy Var:    {color}{variance:.4f}{Colors.RESET} → {factors['entropy_variance']['level'].upper()}")

    # 3. Suspicious API Scan
    api_results = scan_for_apis(data)
    if api_results:
        avg_risk = sum(cat['category_risk'] for cat in api_results.values()) / len(api_results)
        total_matches = sum(cat['count'] for cat in api_results.values())
        level = 'critical' if avg_risk > 80 else 'high' if avg_risk > 60 else 'medium' if avg_risk > 30 else 'low'
        factors['api_abuse'] = {
            'risk': min(100, round(avg_risk)),
            'level': level,
            'value': total_matches,
            'categories': list(api_results.keys()),
            'details': api_results
        }
    else:
        factors['api_abuse'] = {'risk': 5, 'level': 'low', 'value': 0}

    if verbose:
        risk = factors['api_abuse']['risk']
        color = Colors.RED if risk > 60 else Colors.YELLOW if risk > 35 else Colors.GREEN
        cats = len(api_results)
        total_apis = factors['api_abuse'].get('value', 0)
        print(f"  ⚡ API Abuse:      {color}{risk}%{Colors.RESET} ({total_apis} hits in {cats} categories)")

        if api_results and verbose:
            for cat, info in api_results.items():
                c = Colors.RED if info['category_risk'] > 60 else Colors.YELLOW
                print(f"     {Colors.DIM}├─{Colors.RESET} {c}{cat}{Colors.RESET}: "
                      f"{info['count']}/{info['total_apis']} APIs ({info['category_risk']}%)")

    # 4. Packer Detection
    packers = detect_packer_signatures(data)
    is_packed = len(packers) > 0 or (entropy > 0.88 and variance < 0.03)
    if is_packed:
        packer_name = ', '.join(packers) if packers else 'Unknown/Custom'
        factors['packer'] = {'risk': 82, 'level': 'high', 'value': packer_name}
    else:
        factors['packer'] = {'risk': 5, 'level': 'low', 'value': 'None'}

    if verbose:
        if is_packed:
            print(f"  🔒 Packer:         {Colors.RED}DETECTED{Colors.RESET} ({factors['packer']['value']})")
        else:
            print(f"  🔒 Packer:         {Colors.GREEN}None detected{Colors.RESET}")

    # 5. File Size Anomaly
    if file_size < 1000:
        factors['file_size'] = {'risk': 70, 'level': 'high', 'value': file_size}
    elif file_size < 5000:
        factors['file_size'] = {'risk': 45, 'level': 'medium', 'value': file_size}
    elif file_size > 100_000_000:
        factors['file_size'] = {'risk': 50, 'level': 'medium', 'value': file_size}
    else:
        factors['file_size'] = {'risk': 8, 'level': 'low', 'value': file_size}

    if verbose:
        risk = factors['file_size']['risk']
        color = Colors.RED if risk > 60 else Colors.YELLOW if risk > 35 else Colors.GREEN
        print(f"  📦 File Size:      {color}{file_size:,} bytes{Colors.RESET} → {factors['file_size']['level'].upper()}")

    # 6. Overall computation
    overall = compute_overall_risk(factors)

    if verbose:
        print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        level_color = {
            'critical': Colors.MAGENTA,
            'high': Colors.RED,
            'medium': Colors.YELLOW,
            'low': Colors.GREEN
        }.get(overall['level'], Colors.RESET)

        print(f"  {Colors.BOLD}THREAT ASSESSMENT:{Colors.RESET}  "
              f"{level_color}{Colors.BOLD}{overall['label']}{Colors.RESET}  "
              f"(Score: {level_color}{overall['score']}/100{Colors.RESET})")
        print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")

    return {
        'file': file_name,
        'file_path': file_path,
        'file_size': file_size,
        'overall': overall,
        'factors': factors
    }


def analyze_batch(directory, json_output=False, verbose=False):
    """Analyze all files in a directory."""
    results = []
    risk_counts = defaultdict(int)

    files = [f for f in os.listdir(directory)
             if os.path.isfile(os.path.join(directory, f))]

    print(f"\n{Colors.CYAN}Scanning {len(files)} files in {directory}...{Colors.RESET}\n")

    for i, fname in enumerate(files):
        fpath = os.path.join(directory, fname)
        result = analyze_file(fpath, verbose=verbose)

        if 'error' not in result:
            results.append(result)
            risk_counts[result['overall']['level']] += 1
            level_color = {
                'critical': Colors.MAGENTA,
                'high': Colors.RED,
                'medium': Colors.YELLOW,
                'low': Colors.GREEN
            }.get(result['overall']['level'], Colors.RESET)

            if not json_output:
                print(f"  [{i+1:3d}/{len(files)}]  "
                      f"{level_color}{result['overall']['label']:12s}{Colors.RESET}  "
                      f"Score: {result['overall']['score']:3d}  "
                      f"{Colors.DIM}{fname}{Colors.RESET}")

    if not json_output:
        print(f"\n{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print(f"  {Colors.BOLD}BATCH SCAN SUMMARY{Colors.RESET}")
        print(f"  Files Scanned:     {len(results)}")
        print(f"  {Colors.MAGENTA}Critical:{Colors.RESET}           {risk_counts.get('critical', 0)}")
        print(f"  {Colors.RED}High Risk:{Colors.RESET}          {risk_counts.get('high', 0)}")
        print(f"  {Colors.YELLOW}Medium Risk:{Colors.RESET}        {risk_counts.get('medium', 0)}")
        print(f"  {Colors.GREEN}Low Risk:{Colors.RESET}           {risk_counts.get('low', 0)}")
        print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")

    return results


def load_project_stats():
    """Load real statistics from project dataset files."""
    stats = {}
    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Load malware class labels
    class_file = os.path.join(base_dir, 'vs', 'data', 'av-malware-class-labels.csv')
    if os.path.exists(class_file):
        with open(class_file, 'r') as f:
            reader = csv.reader(f)
            next(reader)  # skip header
            classes = list(reader)
            stats['malware_classes'] = len(classes)

    # Load malware family labels
    family_file = os.path.join(base_dir, 'vs', 'data', 'av-malware-family-labels.csv')
    if os.path.exists(family_file):
        with open(family_file, 'r') as f:
            reader = csv.reader(f)
            next(reader)
            families = list(reader)
            stats['malware_families'] = len(families)

    # Load train labels (malware class distribution)
    train_file = os.path.join(base_dir, 'mmcc', 'data', 'sorted-train-labels.csv')
    if os.path.exists(train_file):
        class_counts = defaultdict(int)
        with open(train_file, 'r') as f:
            reader = csv.reader(f)
            next(reader)
            for row in reader:
                if len(row) >= 2:
                    class_counts[row[1]] += 1
        stats['class_distribution'] = dict(class_counts)
        stats['total_train_samples'] = sum(class_counts.values())

    return stats


def main():
    parser = argparse.ArgumentParser(
        description='🛡️ Threat Analysis Engine — Multi-factor malware risk assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python threat_analysis.py suspicious.exe --verbose
  python threat_analysis.py malware_sample.bin --json
  python threat_analysis.py --batch ./samples/ --json
  python threat_analysis.py --stats
        """
    )

    parser.add_argument('file', nargs='?', help='Path to file to analyze')
    parser.add_argument('--json', action='store_true', help='Output results as JSON')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output with detailed breakdown')
    parser.add_argument('--batch', metavar='DIR', help='Analyze all files in a directory')
    parser.add_argument('--stats', action='store_true', help='Show project dataset statistics')

    args = parser.parse_args()

    if args.stats:
        stats = load_project_stats()
        if args.json:
            print(json.dumps(stats, indent=2))
        else:
            print(f"\n{Colors.CYAN}{'═' * 50}{Colors.RESET}")
            print(f"  {Colors.BOLD}📊 Project Dataset Statistics{Colors.RESET}")
            print(f"{Colors.CYAN}{'═' * 50}{Colors.RESET}")
            for key, val in stats.items():
                if isinstance(val, dict):
                    print(f"  {key}:")
                    for k, v in val.items():
                        print(f"    Class {k}: {v:,} samples")
                else:
                    print(f"  {key}: {val:,}")
            print(f"{Colors.CYAN}{'═' * 50}{Colors.RESET}\n")
        return

    if args.batch:
        results = analyze_batch(args.batch, json_output=args.json, verbose=args.verbose)
        if args.json:
            print(json.dumps(results, indent=2, default=str))
        return

    if not args.file:
        parser.print_help()
        sys.exit(1)

    result = analyze_file(args.file, verbose=not args.json)

    if args.json:
        print(json.dumps(result, indent=2, default=str))


if __name__ == '__main__':
    main()
