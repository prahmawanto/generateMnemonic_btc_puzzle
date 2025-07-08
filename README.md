# Bitcoin Address Generator & Checker

A Python script that generates random Bitcoin addresses and checks if they match predefined target addresses.

## Features

- Generates BIP39-compliant mnemonic passphrases (24 words)
- Converts passphrases to Bitcoin private keys
- Derives both compressed and uncompressed public keys
- Generates corresponding P2PKH Bitcoin addresses
- Checks generated addresses against a target list
- Saves successful matches to a file

## Technical Details

### Key Generation Process
1. **Mnemonic Generation**: Uses 256-bit entropy to create a 24-word BIP39 passphrase
2. **Seed Creation**: Converts mnemonic to seed using PBKDF2-HMAC-SHA512
3. **Private Key**: SHA-256 hash of the seed
4. **Public Key**: Derived using ECDSA with SECP256k1 curve
5. **Address Generation**:
   - Compressed: Starts with 0x02/0x03 prefix
   - Uncompressed: Starts with 0x04 prefix
   - Both use SHA-256 → RIPEMD-160 hashing
   - Base58Check encoding with network byte (0x00 for mainnet)

## Requirements

- Python 3.6+
- Required packages:
  ```bash
  pip install mnemonic ecdsa base58
