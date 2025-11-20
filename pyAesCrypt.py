#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pyAesCrypt BruteForce Tool v2.2 (2024+ Compatible)
Multi-process AES decryption brute force tool with virtual environment auto-setup
"""

import os
import sys
import time
import argparse
import threading
import itertools
import string
import subprocess
import tempfile
import multiprocessing as mp

# ---------------- Virtual Environment Setup ----------------
def setup_virtual_environment():
    """Setup virtual environment and install dependencies"""
    venv_path = "aes_brute_venv"
    
    # Check if already in virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        return True
        
    # Create virtual environment
    if not os.path.exists(venv_path):
        print("[*] Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", venv_path], check=True, capture_output=True)
    
    # Determine virtual environment paths
    if os.name == 'nt':  # Windows
        python_path = os.path.join(venv_path, "Scripts", "python.exe")
        pip_path = os.path.join(venv_path, "Scripts", "pip.exe")
    else:  # Linux/Mac
        python_path = os.path.join(venv_path, "bin", "python")
        pip_path = os.path.join(venv_path, "bin", "pip")
    
    # Install pyAesCrypt
    print("[*] Installing pyAesCrypt...")
    result = subprocess.run([pip_path, "install", "pyAesCrypt"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Installation failed: {result.stderr}")
        return False
    
    # Re-execute with virtual environment
    print("[*] Restarting with virtual environment...")
    os.execv(python_path, [python_path] + sys.argv)

# Setup virtual environment before imports
if __name__ == "__main__":
    setup_virtual_environment()

# Now import pyAesCrypt
try:
    import pyAesCrypt
except ImportError:
    print("[!] pyAesCrypt import failed. Please install manually: pip install pyAesCrypt")
    sys.exit(1)

# ---------------- Colors ----------------
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ---------------- Global for worker ----------------
GLOBAL_TARGET_FILE = None
GLOBAL_BUFFER_SIZE = 64 * 1024
GLOBAL_TMPDIR = None

def _mp_worker_try(password):
    """
    Worker process: Attempt decryption with given password
    Returns password if successful, None otherwise
    """
    import os
    try:
        pid = os.getpid()
        tmp_out = os.path.join(GLOBAL_TMPDIR, f"pyaes_tmp_{pid}.bin")
        # pyAesCrypt.decryptFile throws exception on wrong password
        pyAesCrypt.decryptFile(GLOBAL_TARGET_FILE, tmp_out, password, GLOBAL_BUFFER_SIZE)
        # Success -> clean up and return password
        if os.path.exists(tmp_out):
            try:
                os.remove(tmp_out)
            except Exception:
                pass
        return password
    except Exception:
        # Failure -> clean up and return None
        try:
            if 'tmp_out' in locals() and os.path.exists(tmp_out):
                os.remove(tmp_out)
        except Exception:
            pass
        return None

# ---------------- Statistics ----------------
class Stats:
    def __init__(self):
        self.start_time = time.time()
        self.attempts = 0
        self.found = False
        self.password = None
        self.lock = threading.Lock()
    def increment(self, n=1):
        with self.lock:
            self.attempts += n
    def set_found(self, pwd):
        with self.lock:
            self.found = True
            self.password = pwd
    def snapshot(self):
        with self.lock:
            elapsed = time.time() - self.start_time
            rate = self.attempts / elapsed if elapsed > 0 else 0
            return {'attempts': self.attempts, 'elapsed': elapsed, 'rate': rate, 'found': self.found, 'password': self.password}

# ---------------- Brute Forcer ----------------
class PyAesBruteForcer:
    def __init__(self, target_file, output_file=None, processes=None, verbose=False, tmpdir=None):
        if not os.path.exists(target_file):
            raise FileNotFoundError(f"Target file not found: {target_file}")
        self.target_file = target_file
        self.output_file = output_file or "decrypted_output.bin"
        self.processes = processes or mp.cpu_count()
        self.verbose = verbose
        self.stats = Stats()
        self.stop_flag = mp.Value('b', False)
        # tmpdir validation/setup
        if tmpdir:
            if not os.path.isdir(tmpdir):
                raise FileNotFoundError(f"Specified tmp directory not found: {tmpdir}")
            if not os.access(tmpdir, os.W_OK):
                raise PermissionError(f"Specified tmp directory not writable: {tmpdir}")
            self.tmpdir = tmpdir
        else:
            self.tmpdir = tempfile.gettempdir()

    # ---------- Password Generators ----------
    def _dict_generator(self, wordlist_file):
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                pwd = line.strip()
                if pwd:
                    yield pwd

    def _brute_generator(self, charset, min_len, max_len):
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                yield ''.join(combo)

    def _mask_generator(self, mask):
        charset_map = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase,
            '?d': string.digits,
            '?s': string.punctuation,
            '?a': string.ascii_letters + string.digits + string.punctuation
        }
        positions = []
        i = 0
        while i < len(mask):
            token2 = mask[i:i+2]
            if token2 in charset_map:
                positions.append(charset_map[token2])
                i += 2
            else:
                positions.append(mask[i])
                i += 1
        for combo in itertools.product(*positions):
            yield ''.join(combo)

    # ---------- Quick Common Password Check ----------
    def quick_try_common(self):
        """Quickly try common passwords based on filename patterns"""
        common_passwords = [
            # Date-based patterns
            '20250806', '120723', '20240806', '20250806_120723',
            '08062025', '072312', '2025', '2024', '0806', '1207',
            # Common backup passwords
            'backup', 'admin', 'password', '123456', 'web', 'web2025',
            'backup2025', 'backup2024', 'webbackup', 'admin123',
            # Simple passwords
            '', '123', '1234', '12345', '12345678', '0000', '1111',
            # Filename-based
            'web_20250806', 'web20250806', 'web_2025'
        ]
        
        print(f"{Colors.CYAN}[*] Quick testing {len(common_passwords)} common passwords...{Colors.END}")
        
        for pwd in common_passwords:
            try:
                if self.verbose:
                    print(f"[Try] '{pwd}'")
                pyAesCrypt.decryptFile(self.target_file, self.output_file, pwd, 64 * 1024)
                print(f"{Colors.GREEN}{Colors.BOLD}[+] Password found: '{pwd}'{Colors.END}")
                return True
            except Exception:
                continue
                
        return False

    # ---------- Core: Multi-process Runner ----------
    def _run_attack_multiprocess(self, password_iterable, chunksize=256):
        global GLOBAL_TARGET_FILE, GLOBAL_TMPDIR
        GLOBAL_TARGET_FILE = self.target_file
        GLOBAL_TMPDIR = self.tmpdir

        workers = max(1, min(self.processes, mp.cpu_count()))
        print(f"{Colors.BLUE}[*] Using {workers} processes, temp directory: {self.tmpdir}{Colors.END}")

        pool = mp.Pool(processes=workers)
        try:
            imap = pool.imap_unordered(_mp_worker_try, password_iterable, chunksize)

            # Progress display thread
            stop_print = threading.Event()
            def _progress():
                while not stop_print.is_set():
                    s = self.stats.snapshot()
                    if s['found']:
                        break
                    elapsed_str = time.strftime('%H:%M:%S', time.gmtime(s['elapsed']))
                    print(f"\r{Colors.CYAN}[*] Attempts: {s['attempts']:,} | Speed: {s['rate']:.0f}/s | Time: {elapsed_str}{Colors.END}", end='', flush=True)
                    time.sleep(1)
            t = threading.Thread(target=_progress)
            t.daemon = True
            t.start()

            for res in imap:
                self.stats.increment(1)
                if res:
                    self.stats.set_found(res)
                    print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Password found: {res}{Colors.END}")
                    pyAesCrypt.decryptFile(self.target_file, self.output_file, res, GLOBAL_BUFFER_SIZE)
                    stop_print.set()
                    pool.terminate()
                    pool.join()
                    return True

                if self.stop_flag.value:
                    stop_print.set()
                    pool.terminate()
                    pool.join()
                    return False

            stop_print.set()
            pool.close()
            pool.join()
            print(f"\n{Colors.RED}[-] No valid password found{Colors.END}")
            return False

        except KeyboardInterrupt:
            print("\n" + Colors.YELLOW + "[*] User interrupted, terminating workers..." + Colors.END)
            self.stop_flag.value = True
            pool.terminate()
            pool.join()
            raise
        except Exception as e:
            try:
                pool.terminate()
                pool.join()
            except Exception:
                pass
            raise e

    # ---------- Public Attack Methods ----------
    def dictionary_attack(self, wordlist_file):
        print(f"{Colors.CYAN}[*] Starting dictionary attack{Colors.END}")
        if not os.path.exists(wordlist_file):
            print(f"{Colors.RED}[!] Wordlist file not found: {wordlist_file}{Colors.END}")
            return False
        gen = self._dict_generator(wordlist_file)
        return self._run_attack_multiprocess(gen)

    def brute_force_attack(self, charset, min_length=1, max_length=4):
        print(f"{Colors.CYAN}[*] Starting brute force attack{Colors.END}")
        print(f"{Colors.BLUE}[*] Charset: {charset}{Colors.END}")
        print(f"{Colors.BLUE}[*] Password length: {min_length}-{max_length}{Colors.END}")
        gen = self._brute_generator(charset, min_length, max_length)
        return self._run_attack_multiprocess(gen)

    def mask_attack(self, mask):
        print(f"{Colors.CYAN}[*] Starting mask attack{Colors.END}")
        gen = self._mask_generator(mask)
        return self._run_attack_multiprocess(gen)

# ---------------- Helpers ----------------
def create_sample_wordlist():
    wordlist = [
        "123456", "password", "123456789", "12345678", "12345",
        "1234567", "1234567890", "qwerty", "abc123", "111111",
        "123123", "admin", "letmein", "welcome", "monkey",
        "20250806", "120723", "backup", "web", "admin123"
    ]
    with open("common_passwords.txt", "w") as f:
        for pwd in wordlist:
            f.write(pwd + "\n")
    print(f"{Colors.GREEN}[+] Sample wordlist created: common_passwords.txt{Colors.END}")

def print_banner():
    banner = rf"""{Colors.CYAN}{Colors.BOLD}
 #####  ######  #####     ######   ####  ######  #####   #####  
 #    #  #      #    #    #       #    #  #      #    # #    # 
 #####   #####  #    #    #####   #    #  #####  #    # #    # 
 #    #  #      #####     #       #    #  #      #####  #    # 
 #    #  #      #   #     #       #    #  #      #   #  #    # 
 #####   ###### #    #    #        ####   ###### #    #  #####  
                                                                
    pyAesCrypt Multi-Process Brute Force Tool v2.2
    
{Colors.END}{Colors.YELLOW}    [*] Auto virtual environment setup (Kali 2024+ compatible)
    [*] Multi-process parallel processing
    [*] Dictionary, brute force, and mask attacks supported
{Colors.END}
"""
    print(banner)

# ---------------- Main ----------------
def main():
    print_banner()
    parser = argparse.ArgumentParser(description="pyAesCrypt Multi-Process Brute Force Tool v2.2")
    parser.add_argument("-f", "--file", required=True, help="Target encrypted file")
    parser.add_argument("-o", "--output", default="decrypted.bin", help="Decrypted output file (default: decrypted.bin)")
    parser.add_argument("-p", "--processes", type=int, default=None, help="Number of processes (default: CPU cores)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--tmp", dest="tmpdir", help="Temporary directory for process files (recommended: tmpfs like /dev/shm)")
    parser.add_argument("--quick", action="store_true", help="Quick common password test first")
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-w", "--wordlist", help="Wordlist file path")
    group.add_argument("-b", "--brute", action="store_true", help="Brute force mode")
    group.add_argument("-m", "--mask", help="Mask attack mode")
    group.add_argument("--create-wordlist", action="store_true", help="Create sample wordlist file")
    
    parser.add_argument("-c", "--charset", default="0123456789", help="Brute force charset (default: digits)")
    parser.add_argument("-l", "--length", default="1-4", help="Password length range (format: min-max, default: 1-4)")

    args = parser.parse_args()

    if args.create_wordlist:
        create_sample_wordlist()
        return

    # Validate tmpdir
    tmpdir = args.tmpdir
    if tmpdir:
        tmpdir = os.path.abspath(tmpdir)
        if not os.path.isdir(tmpdir):
            print(f"{Colors.RED}[!] Specified tmp directory not found: {tmpdir}{Colors.END}")
            sys.exit(1)
        if not os.access(tmpdir, os.W_OK):
            print(f"{Colors.RED}[!] Specified tmp directory not writable: {tmpdir}{Colors.END}")
            sys.exit(1)

    try:
        bruteforcer = PyAesBruteForcer(
            target_file=args.file,
            output_file=args.output,
            processes=args.processes,
            verbose=args.verbose,
            tmpdir=tmpdir
        )

        success = False
        start_time = time.time()

        # Quick common password test
        if args.quick:
            success = bruteforcer.quick_try_common()
            if success:
                elapsed = time.time() - start_time
                print(f"{Colors.GREEN}[+] Quick mode success! Time: {elapsed:.2f}s{Colors.END}")
                sys.exit(0)

        # Main attack modes
        if args.wordlist:
            success = bruteforcer.dictionary_attack(args.wordlist)
        elif args.brute:
            min_len, max_len = map(int, args.length.split('-'))
            success = bruteforcer.brute_force_attack(args.charset, min_len, max_len)
        elif args.mask:
            success = bruteforcer.mask_attack(args.mask)
        else:
            # Default to quick common passwords if no mode specified
            success = bruteforcer.quick_try_common()

        elapsed = time.time() - start_time
        stats = bruteforcer.stats.snapshot()

        print(f"\n{Colors.CYAN}=== Attack Complete ==={Colors.END}")
        print(f"{Colors.BLUE}Total attempts: {stats['attempts']:,}{Colors.END}")
        print(f"{Colors.BLUE}Total time: {time.strftime('%H:%M:%S', time.gmtime(elapsed))}{Colors.END}")
        print(f"{Colors.BLUE}Average speed: {stats['rate']:.0f} passwords/sec{Colors.END}")

        if success:
            print(f"{Colors.GREEN}{Colors.BOLD}Status: Password successfully found!{Colors.END}")
            sys.exit(0)
        else:
            print(f"{Colors.RED}Status: No password found{Colors.END}")
            sys.exit(1)

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] User interrupted attack{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
