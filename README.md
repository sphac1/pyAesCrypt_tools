# pyAesCrypt Brute Force Tool

A high-performance, multi-process brute force tool for decrypting pyAesCrypt encrypted files. Automatically handles virtual environment setup and supports multiple attack modes.

## Features

- 🚀 **Multi-process parallel processing** for maximum performance
- 🛡️ **Auto virtual environment setup** (Kali 2024+ compatible)
- 📦 **Multiple attack modes**: Dictionary, brute force, and mask attacks
- ⚡ **Quick common password testing** for fast results
- 📊 **Real-time progress statistics** with speed monitoring
- 💾 **Configurable temp directories** for optimal I/O performance
- 🎨 **Color-coded output** for better readability

## Quick Start

bash

```
# Make script executable
chmod +x pyAesCrypt.py

# Quick test with common passwords
python3 pyAesCrypt.py -f encrypted_file.aes --quick

# Dictionary attack
python3 pyAesCrypt.py -f encrypted_file.aes -w passwords.txt

# Brute force numbers
python3 pyAesCrypt.py -f encrypted_file.aes -b -c "0123456789" -l "4-8"
```



## Installation

The tool automatically sets up a virtual environment and installs dependencies on first run. No manual installation required!

## Usage

### Basic Syntax

```
python3 pyAesCrypt.py -f <encrypted_file> [options] [attack_mode]
```



### Attack Modes

#### 1. Quick Common Passwords

```
python3 pyAesCrypt.py -f encrypted_file.aes --quick
```



#### 2. Dictionary Attack

```
python3 pyAesCrypt.py -f encrypted_file.aes -w passwords.txt
```



#### 3. Brute Force Attack

```
# Numbers only, length 4-8
python3 pyAesCrypt.py -f encrypted_file.aes -b -c "0123456789" -l "4-8"

# Alphanumeric
python3 pyAesCrypt.py -f encrypted_file.aes -b -c "abcdefghijklmnopqrstuvwxyz0123456789" -l "3-6"
```



#### 4. Mask Attack

```
# 2 lowercase + 2 digits
python3 pyAesCrypt.py -f encrypted_file.aes -m "?l?l?d?d"

# 1 uppercase + 3 digits + 1 special
python3 pyAesCrypt.py -f encrypted_file.aes -m "?u?d?d?d?s"
```



### Mask Syntax

- `?l` - lowercase letters (a-z)
- `?u` - uppercase letters (A-Z)
- `?d` - digits (0-9)
- `?s` - special characters (!@#$% etc.)
- `?a` - all characters (letters + digits + specials)

## Command Line Options

### Required Arguments

- `-f, --file` - Target encrypted file (required)

### Output Options

- `-o, --output` - Output file for decrypted content (default: decrypted.bin)
- `--tmp` - Temporary directory for process files (recommended: /dev/shm for tmpfs)

### Performance Options

- `-p, --processes` - Number of worker processes (default: CPU cores)
- `-v, --verbose` - Enable verbose output

### Attack Mode Options

- `--quick` - Quick common password test first
- `-w, --wordlist` - Wordlist file for dictionary attack
- `-b, --brute` - Enable brute force mode
- `-m, --mask` - Mask pattern for mask attack
- `-c, --charset` - Character set for brute force (default: "0123456789")
- `-l, --length` - Password length range "min-max" (default: "1-4")

### Utility Options

- `--create-wordlist` - Create a sample wordlist file

## Examples

### Basic Usage

```
# Quick test with common passwords
python3 pyAesCrypt.py -f backup.zip.aes --quick

# Dictionary attack with custom wordlist
python3 pyAesCrypt.py -f config.aes -w my_passwords.txt -o decrypted_config.txt

# High-performance brute force
python3 pyAesCrypt.py -f database.aes -b -c "0123456789" -l "6-8" -p 8 --tmp /dev/shm
```



### Advanced Scenarios

```
# Comprehensive attack strategy
# 1. First, try quick common passwords
python3 pyAesCrypt.py -f target.aes --quick

# 2. If quick fails, try dictionary attack
python3 pyAesCrypt.py -f target.aes -w /usr/share/wordlists/rockyou.txt

# 3. Finally, brute force with optimal settings
python3 pyAesCrypt.py -f target.aes -b -c "abcdefghijklmnopqrstuvwxyz0123456789" -l "4-6" -p 12
```



### Performance Tuning

```
# Maximum performance on high-core systems
python3 pyAesCrypt.py -f large_file.aes -w big_wordlist.txt -p 16 --tmp /dev/shm

# Balanced performance for general use
python3 pyAesCrypt.py -f medium_file.aes -w common_passwords.txt -p 8

# Low-resource mode
python3 pyAesCrypt.py -f small_file.aes -b -c "0123456789" -l "1-4" -p 2
```



## Performance Tips

1. **Use tmpfs for temp directory** when possible:

   ```
   --tmp /dev/shm
   ```

   

2. **Adjust process count** based on your CPU:

   - 4-8 cores: `-p 4`
   - 8-16 cores: `-p 8`
   - 16+ cores: `-p 12-16`

3. **Start with quick mode** to catch easy passwords quickly

4. **Use appropriate character sets** to reduce search space

## Output Example

```
[*] Quick testing 25 common passwords...
[+] Password found: 'backup2024'

=== Attack Complete ===
Total attempts: 15
Total time: 00:00:03
Average speed: 5 passwords/sec
Status: Password successfully found!
```



## Troubleshooting

### Common Issues

1. **Virtual Environment Creation Fails**
   - Ensure Python 3.8+ is installed
   - Check disk space in current directory
   - Run with `sudo` if permission issues
2. **Performance is Slow**
   - Use `--tmp /dev/shm` for faster I/O
   - Increase `-p` value for more CPU cores
   - Use SSD storage for wordlist files
3. **No Password Found**
   - Try different character sets
   - Increase password length range
   - Use larger, more comprehensive wordlists

### Debug Mode

For troubleshooting, run with verbose output:

```
python3 pyAesCrypt.py -f target.aes -w wordlist.txt -v
```



## Legal & Ethical Use

This tool is intended for:

- Security research and education
- Authorized penetration testing
- Personal data recovery
- Legal forensic investigations

**⚠️ Warning**: Only use on files you own or have explicit permission to test. Unauthorized decryption attempts may violate laws and regulations.

## Support

For issues and questions:

1. Check the troubleshooting section above
2. Review the script's help: `python3 pyAesCrypt.py --help`
3. Ensure you're using the correct file format (.aes encrypted by pyAesCrypt)

------

**Note**: First run may take longer as it sets up the virtual environment. Subsequent runs will be faster.
