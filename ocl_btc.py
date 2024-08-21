import pyopencl as cl
import numpy as np
import hashlib
import os
import time
import ecdsa
import base58
import warnings
import argparse

# Part of being paranoid is writing your own code.
# Because I don't trust anybody.
# Let's generate our bitcoin wallets using OpenCL.
# Pull some data from the frame buffers of the gpu to seed.
# run this 8192 times. Include date, unix epoch time. True random.
# Thanks AMD. 
# <3 


# Suppress specific warnings from pyopencl
def suppress_pyopencl_warnings():
    warnings.filterwarnings("ignore", category=UserWarning, module='pyopencl')

suppress_pyopencl_warnings()

# OpenCL Kernel Code
kernel_code = """
__kernel void generate_random_data(__global unsigned char *data, int width, int height) {
    int id = get_global_id(0);
    int x = id % width;
    int y = id / width;

    if (x >= width || y >= height) return;

    // Initialize seed based on position and ID
    unsigned int seed = (x * y + id + get_global_id(1)) * 0x87654321;

    // Perform 8192 rounds of mixing
    for (int i = 0; i < 8192; ++i) {
        seed = (seed * 1103515245 + 12345) % 0x100000000;
    }

    // Output the highest byte of the seed as random data
    data[id] = (unsigned char)(seed >> 24);
}
"""

def initialize_opencl():
    platforms = cl.get_platforms()
    platform = platforms[0]
    devices = platform.get_devices(cl.device_type.GPU)
    device = devices[0]
    context = cl.Context([device])
    queue = cl.CommandQueue(context)
    program = cl.Program(context, kernel_code).build()
    return context, queue, program

def generate_random_data_from_gpu(width, height):
    context, queue, program = initialize_opencl()
    num_elements = width * height
    data = np.empty(num_elements, dtype=np.uint8)
    
    mf = cl.mem_flags
    data_buffer = cl.Buffer(context, mf.WRITE_ONLY, data.nbytes)
    
    kernel = program.generate_random_data
    kernel.set_args(data_buffer, np.int32(width), np.int32(height))
    cl.enqueue_nd_range_kernel(queue, kernel, (num_elements,), None)
    cl.enqueue_copy(queue, data, data_buffer).wait()
    
    return data

def generate_private_key():
    width, height = 32, 32  # Dimensions for generating random data
    random_data = generate_random_data_from_gpu(width, height)
    
    # Additional entropy sources
    os_random_bytes = os.urandom(32)
    current_time = str(time.time()).encode('utf-8')
    current_data = os.popen("wmic os get /value").read().encode('utf-8')  # Example command for Windows, change if necessary

    # Combine all entropy sources
    combined_entropy = bytearray(random_data) + bytearray(os_random_bytes) + current_time + current_data
    
    # Hash to ensure randomness
    private_key = hashlib.sha256(combined_entropy).hexdigest()
    return private_key[:64]  # Ensure the key is 64 hex characters (256 bits)

def generate_wif_key(private_key):
    # Convert private key to bytes and add network byte
    private_key_bytes = bytes.fromhex(private_key)
    network_byte = b'\x80' + private_key_bytes
    
    # Perform SHA256 twice
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    
    # Append checksum to the end of network byte-prefixed private key
    wif_bytes = network_byte + checksum
    
    # Encode in Base58
    wif_key = base58.b58encode(wif_bytes).decode('utf-8')
    return wif_key

def generate_public_key(private_key):
    # Generate public key from private key using ECDSA
    private_key_bytes = bytes.fromhex(private_key)
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()  # Prefix with 0x04 for uncompressed format
    return public_key

def generate_bitcoin_address(public_key):
    # Perform SHA256 followed by RIPEMD160 hash on the public key
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    
    # Add network byte (0x00 for Bitcoin mainnet)
    network_byte = b'\x00' + ripemd160
    
    # Perform SHA256 twice for checksum
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    
    # Concatenate network byte, RIPEMD160 hash, and checksum
    address_bytes = network_byte + checksum
    
    # Encode in Base58
    bitcoin_address = base58.b58encode(address_bytes).decode('utf-8')
    return bitcoin_address

def generate_wallets(num_wallets):
    for i in range(num_wallets):
        private_key = generate_private_key()
        wif_key = generate_wif_key(private_key)
        public_key = generate_public_key(private_key)
        bitcoin_address = generate_bitcoin_address(public_key)
        
        print(f"Wallet {i+1}:")
        print(f"Private Key (WIF): {wif_key}")
        print(f"Public Key: {public_key.hex()}")
        print(f"Bitcoin Address: {bitcoin_address}\n")

def main():
    parser = argparse.ArgumentParser(description="Generate Bitcoin wallets")
    parser.add_argument('num_wallets', type=int, help="Number of wallets to generate")
    args = parser.parse_args()

    print("Generating wallets...\n")
    generate_wallets(args.num_wallets)
    print("Wallet generation complete.")
    print("\nCredit: _SiCK https://afflicted.sh")

if __name__ == "__main__":
    main()
