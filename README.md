# Secure XOR Encryption Tool version 001

This project is a Rust-based encryption and decryption tool that implements a secure version of XOR encryption. It is designed to approximate a One-Time Pad (OTP) while mitigating the typical vulnerabilities associated with basic XOR encryption. The tool works with raw binary data, making it suitable for encrypting and decrypting any type of file.

## Table of Contents
- [Overview](#overview)
- [How It Works](#how-it-works)
  - [Encryption Process](#encryption-process)
  - [Decryption Process](#decryption-process)
- [Key Features](#key-features)
- [Usage](#usage)
  - [Building the Project](#building-the-project)
  - [Encrypting a File](#encrypting-a-file)
  - [Decrypting a File](#decrypting-a-file)
- [Examples](#examples)
  - [Encrypting a File](#encrypting-a-file-example)
  - [Decrypting a File](#decrypting-a-file-example)
  - [Notes on File Types](#notes-on-file-types)
- [Security Considerations](#security-considerations)
- [Attack Vectors on XOR and How This Tool Mitigates Them](#attack-vectors-on-xor-and-how-this-tool-mitigates-them)
- [Considerations for Executable Files](#considerations-for-executable-files)
- [License](#license)

## Overview

This tool encrypts and decrypts files using a combination of a key file and a generated keystream derived from a nonce. It incorporates several cryptographic best practices to enhance the security of XOR encryption, including the use of a nonce, a pseudorandom keystream generator, and HMAC-SHA256 for integrity verification.

## How It Works

### Encryption Process
1. **Load the Key File**: A key file containing random bytes is loaded. The key must be at least as long as the plaintext file. You make your own key file- and used properly it has the potential of being a true One TIme Pad- unbreakable in theory- so far nothing has cracked a true one time pad. 
2. **Generate a Random Nonce**: A 128-bit (16-byte) nonce is randomly generated for each encryption operation, ensuring unique ciphertexts for identical plaintexts.
3. **Generate a Keystream**: A pseudorandom keystream is generated using SHA-256 in counter mode until the length matches the plaintext.
4. **Dual XOR Operation**:
   - The plaintext is XORed with the key file.
   - The result is then XORed with the generated keystream.
5. **Concatenate Nonce and Ciphertext**: The nonce is prepended to the ciphertext for use during decryption.
6. **Derive HMAC Key**: An HMAC key is derived from the key file using SHA-256 to ensure key separation.
7. **Compute HMAC**: An HMAC-SHA256 tag is computed over the concatenated nonce and ciphertext for integrity verification.
8. **Append HMAC to Output**: The HMAC tag is appended to the output data.

### Decryption Process
1. **Load the Key File**: The same key file used during encryption is loaded.
2. **Extract Nonce, Ciphertext, and HMAC**: The input data is split into nonce, ciphertext, and received HMAC tag.
3. **Derive HMAC Key**: The HMAC key is derived from the key file.
4. **Verify HMAC**: The received HMAC tag is verified against the concatenated nonce and ciphertext. If verification fails, the program exits to prevent tampering.
5. **Generate Keystream**: The keystream is generated using the nonce.
6. **Dual XOR Operation**: The ciphertext is XORed with the keystream and the key file to retrieve the plaintext.

## Key Features
- **Raw Binary Processing**: Handles raw binary data, allowing encryption and decryption of any file type.
- **One-Time Pad Approximation**: Uses a key file as long as the plaintext, combining it with a generated keystream to enhance security.
- **Nonce Implementation**: Incorporates a unique nonce for each encryption to ensure different ciphertexts even with the same plaintext and key.
- **Integrity Verification**: Utilizes HMAC-SHA256 to verify the integrity and authenticity of the encrypted data.
- **Simple Dependencies**: Relies on well-established cryptographic primitives available in Rust crates.

## Usage

### Building the Project
Ensure you have Rust and Cargo installed. Clone the repository and build the project using Cargo:
```sh
cargo build --release
```

### Encrypting a File
To encrypt a file:
```sh
./xor E <input_file> <output_file> <key_file>
```
- `<input_file>`: The path to the plaintext file you want to encrypt.
- `<output_file>`: The path where the ciphertext will be saved.
- `<key_file>`: The path to the key file containing random bytes.

### Decrypting a File
To decrypt a file:
```sh
./xor D <input_file> <output_file> <key_file>
```
- `<input_file>`: The path to the ciphertext file you want to decrypt.
- `<output_file>`: The path where the decrypted plaintext will be saved.
- `<key_file>`: The path to the same key file used during encryption.

## Examples

### Encrypting a File Example
Suppose you have a plaintext file `secret.txt` and a key file `keyfile.bin`:
```sh
./xor E secret.txt secret_encrypted.bin keyfile.bin
```
This command encrypts `secret.txt` and saves the ciphertext to `secret_encrypted.bin`.

### Decrypting a File Example
To decrypt the previously encrypted file:
```sh
./xor D secret_encrypted.bin secret_decrypted.txt keyfile.bin
```
This command decrypts `secret_encrypted.bin` and saves the plaintext to `secret_decrypted.txt`.

### Notes on File Types
- **Binary Files**: The tool processes raw binary data, allowing encryption and decryption of any file type, including images, videos, executables, etc.
- **Key File Generation**: Ensure that your key file (`keyfile.bin`) contains random bytes and is at least as long as the largest file you intend to encrypt.

## Security Considerations

### 1. Proper Keystream Generation
- **SHA-256 in Counter Mode**: Uses the SHA-256 hash function in counter mode to generate a pseudorandom keystream.
- **Avoids Argon2 Misuse**: Avoids misuse of Argon2 (a password hashing algorithm) for keystream generation.

### 2. Nonce Utilization
- **Ciphertext Uniqueness**: Incorporates a random nonce for each encryption, ensuring unique ciphertexts.
- **Mitigates XOR Vulnerabilities**: Helps prevent attackers from exploiting patterns in the ciphertext.

### 3. Dual XOR Operation
- **Combines Key and Keystream**: Enhances security by XORing the plaintext with both the key file and the generated keystream.

### 4. Separate HMAC Key Derivation
- **Key Separation**: Derives an HMAC key from the key file using SHA-256, preventing key reuse vulnerabilities.

### 5. Integrity and Authentication
- **HMAC-SHA256**: Provides a robust method for verifying the integrity of the ciphertext and nonce.
- **Tamper Detection**: Any modification to the data results in HMAC verification failure during decryption.

### 6. Simplified Dependencies
- **Removed Unnecessary Crates**: Eliminates unused dependencies like Argon2, resulting in cleaner code.

### 7. Performance and Practicality
- **Efficient Keystream Generation**: Uses SHA-256 for good performance, even on large files.

### 8. Adherence to Cryptographic Principles
- **Avoids Misusing Cryptographic Functions**: Uses primitives for their intended purpose, adhering to security best practices.

## Attack Vectors on XOR and How This Tool Mitigates Them

### 1. XORing Two Ciphertexts (Crib-Dragging Attack)
In a traditional XOR cipher, if an attacker can obtain two ciphertexts that were encrypted with the same key, they can XOR them together to effectively cancel out the key. This results in the XOR of the two original plaintexts, which can be exploited using language properties or statistical analysis to recover the plaintexts.

**Mitigation in This Tool**:
- The use of a random nonce ensures that even if the same plaintext is encrypted twice with the same key file, the resulting ciphertexts will be different due to the nonce-based keystream generation. This makes it impossible for an attacker to perform a successful crib-dragging attack.

### 2. Known Plaintext Attack
If an attacker has access to both a plaintext and its corresponding ciphertext, they can XOR them together to reveal the key material. If the same key is reused, this information can be used to decrypt other messages encrypted with the same key.

**Mitigation in This Tool**:
- This tool approximates a one-time pad by requiring that the key file be at least as long as the plaintext, and ideally used only once. This practice ensures that key reuse is avoided, mitigating the risk of known plaintext attacks.
- Additionally, the dual XOR operation with both the key file and the nonce-derived keystream makes the effective key different for every encryption operation.

### 3. Repeated Key Usage
Repeated key usage is one of the primary weaknesses of XOR encryption. When the same key is used to encrypt multiple plaintexts, it becomes possible to apply statistical analysis to discover the key or extract information about the plaintexts.

**Mitigation in This Tool**:
- The inclusion of a nonce for each encryption operation ensures that even if the key file is reused, the resulting ciphertexts will differ. This nonce, combined with the keystream generation, effectively changes the encryption key for each message, mitigating the risks associated with repeated key usage.

### 4. Integrity Attacks
Basic XOR encryption provides no integrity checks, making it possible for an attacker to modify the ciphertext without detection. Such modifications can lead to manipulated plaintext upon decryption.

**Mitigation in This Tool**:
- The use of HMAC-SHA256 for integrity verification ensures that any modification to the ciphertext, nonce, or any part of the data will be detected during decryption. The decryption process verifies the HMAC tag, and if verification fails, the tool will exit, preventing tampered data from being processed.

## Considerations for Executable Files

Encryption and decryption operations that prepend and append data can present risks when dealing with executable files. Even a single byte being altered in an executable can render it inoperative or cause unexpected behavior. Since this tool prepends a nonce and appends an HMAC to the output, executable files can be particularly sensitive to such modifications.

**Recommendation**: To safely encrypt executable files, it is advisable to first compress them (e.g., using a tool like `zip`) before encryption. Compression packages the executable into a new format, protecting the internal structure from direct modification during the encryption process. This ensures that, upon decryption, the executable remains intact and fully operational after being extracted from the compressed archive.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

