
# OpenCL-based Bitcoin Private Key Generator

This project provides an OpenCL-based entropy gathering and SHA-256 hashing implementation for generating secure Bitcoin private keys. The code uses hardware-accelerated entropy gathering and hashing, leveraging GPU resources through OpenCL for high performance. It also includes Python utilities for managing Wallet Import Format (WIF), Bitcoin address generation, and verification.

## Features

- **OpenCL-based Entropy Gathering**: Collects high-quality entropy from various sources such as pixel data, memory blocks, and time-based seeds to ensure randomness.
- **OpenCL SHA-256 Hashing**: Implements SHA-256 hashing in OpenCL for high-speed cryptographic operations.
- **Double SHA-256 Hashing**: The private key generation process includes double SHA-256 hashing for enhanced security, following the Bitcoin standard.
- **WIF and Bitcoin Address Generation**: Provides functions to generate a Bitcoin private key, compress the corresponding public key, generate the Bitcoin address, and export the private key in Wallet Import Format (WIF).
- **Bitcoin Address Verification**: Includes functionality to verify that a Bitcoin address derived from a WIF matches the original address.

## Kernel Overview

### `gather_entropy.cl`

The `gather_entropy` kernel is responsible for gathering entropy from various inputs:

- **Input Sources**: Entropy is collected from a time-based seed, pixel data, and memory blocks. 
- **Perturbation**: Complex bitwise operations, such as rotations and shifts, are used to mix the entropy for greater randomness.
- **Performance Optimizations**: Loop unrolling and bitwise manipulations ensure that the entropy gathering process is both fast and secure.

### `sha256.cl`

The `sha256` kernel implements the standard 64-round SHA-256 algorithm:

- **64 Rounds**: The kernel performs the full SHA-256 compression process, producing a cryptographic hash from input data.
- **Message Preparation**: Data is divided into 64-byte blocks, extended, and then hashed.
- **Final Hash**: After processing, the final 256-bit hash is written to the output buffer.

## Python Overview

### Functions

- **`create_opencl_context`**: Initializes the OpenCL context and selects the best available GPU device.
- **`compile_kernel`**: Compiles the OpenCL kernel from a `.cl` file.
- **`gather_entropy`**: Calls the OpenCL `gather_entropy` kernel to collect entropy.
- **`sha256_hash`**: Computes a single SHA-256 hash using the OpenCL `sha256` kernel.
- **`double_sha256`**: Performs a double SHA-256 hash, as required in Bitcoin private key generation.
- **`generate_wif`**: Generates a Wallet Import Format (WIF) string from a private key.
- **`compress_public_key`**: Compresses a public key to its 33-byte format.
- **`generate_private_key`**: Gathers entropy, applies double SHA-256, and generates a 32-byte private key.
- **`generate_bitcoin_address_and_wif`**: Generates a Bitcoin address and WIF from the private key.
- **`verify_bitcoin_address_from_wif`**: Verifies that a Bitcoin address matches the address derived from a WIF.

### Workflow

1. **Entropy Gathering**: Entropy is collected from a combination of time-based seeds, pixel data, and memory blocks using the `gather_entropy` OpenCL kernel.
   
2. **Double SHA-256**: The gathered entropy is passed through the `sha256` OpenCL kernel twice (double SHA-256 hashing) to generate the final private key.

3. **Bitcoin Address and WIF**: The private key is then used to generate a compressed public key, which is hashed to produce a Bitcoin address. The private key is also encoded in WIF format for backup or import into other Bitcoin wallets.

4. **Address Verification**: The address derived from the WIF is verified to match the original address, ensuring consistency.

## Usage

### Prerequisites

- Python 3.x
- `pyopencl` library for OpenCL support.
- A GPU supporting  (Nvidia/AMD/ATI) OpenCL.

### Installation

```bash
pip install pyopencl ecdsa base58 numpy
```

### Running the Script

```bash
python generate_bitcoin_keys.py
```

This will generate a Bitcoin private key, Bitcoin address, and WIF.

### Example Output

```bash
Entropy (hex): cdf0324a3b5d2a9b6f8c720b5e1ad7fbe1a834fce34d...
Private Key (hex): 1e99423a4ed27608a15a2616c0e7d06df5e0c0e7e3c...
Bitcoin Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
WIF: L1aW4aubDFB7yfras2S1mN3bqg9e2pHBNp7LwMPssBjDF
```

### Verifying Address

The script automatically verifies that the address generated from the WIF matches the original Bitcoin address.

### Kernel Compilation

The OpenCL kernels are located in `entropy_sha256.cl`. Ensure that the `.cl` file is in the same directory as the Python script.

### Clean-up

The script will automatically clean up OpenCL resources at the end of execution.

## License

This project is licensed under the MIT License.
