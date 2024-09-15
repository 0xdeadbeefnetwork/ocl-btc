import warnings
import numpy as np
import pyopencl as cl
import hashlib
import base58
import ecdsa
from ecdsa import SECP256k1
import os

warnings.filterwarnings("ignore", category=UserWarning)
os.environ['PYOPENCL_NO_CACHE'] = '1'

def create_opencl_context():
    """Create and return the best available OpenCL context, queue, and device."""
    platforms = cl.get_platforms()
    for platform in platforms:
        devices = platform.get_devices(device_type=cl.device_type.GPU)
        if devices:
            context = cl.Context(devices=devices)
            queue = cl.CommandQueue(context)
            return context, queue, devices[0]
    raise RuntimeError("No OpenCL-capable GPU found")

def compile_kernel(context, kernel_file):
    """Compile the OpenCL kernel from a .cl file and return the program."""
    with open(kernel_file, 'r') as f:
        kernel_code = f.read()
    return cl.Program(context, kernel_code).build()

def gather_entropy(context, queue, program, mem_block, pixel_data, global_size):
    """Gather entropy using the provided OpenCL context and kernel."""
    entropy = np.zeros(global_size, dtype=np.uint64)
    time_seed = np.random.randint(0, 2**64, size=global_size, dtype=np.uint64)  # Secure random time seed
    mf = cl.mem_flags
    
    # Initialize buffers
    mem_block_buffer = cl.Buffer(context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=mem_block)
    entropy_buffer = cl.Buffer(context, mf.WRITE_ONLY, entropy.nbytes)
    time_seed_buffer = cl.Buffer(context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=time_seed)
    pixel_data_buffer = cl.Buffer(context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=pixel_data)

    # Run the kernel
    program.gather_entropy(queue, (global_size,), None, entropy_buffer, mem_block_buffer, time_seed_buffer, pixel_data_buffer, np.uint32(pixel_data.size))
    cl.enqueue_copy(queue, entropy, entropy_buffer).wait()

    return entropy

def sha256_hash(context, queue, program, data):
    """Compute a SHA-256 hash using the provided OpenCL context and kernel."""
    data = np.frombuffer(data, dtype=np.uint8)
    num_blocks = (len(data) + 63) // 64  # Number of 64-byte blocks
    output = np.zeros(32, dtype=np.uint8)
    mf = cl.mem_flags
    data_buffer = cl.Buffer(context, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=data)
    output_buffer = cl.Buffer(context, mf.WRITE_ONLY, output.nbytes)
    
    program.sha256(queue, (num_blocks,), None, data_buffer, output_buffer, np.uint32(num_blocks))
    cl.enqueue_copy(queue, output, output_buffer).wait()

    return output.tobytes()  # Convert the output to bytes

def double_sha256(context, queue, program, data):
    """Perform a double SHA-256 hash on the provided data."""
    return sha256_hash(context, queue, program, sha256_hash(context, queue, program, data))

def wif_checksum(data):
    """Calculate the WIF checksum for a given data."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]

def generate_wif(private_key_bytes):
    """Generate a Wallet Import Format (WIF) string from a private key."""
    versioned_private_key = b'\x80' + private_key_bytes
    checksum = wif_checksum(versioned_private_key)
    return base58.b58encode(versioned_private_key + checksum).decode('ascii')

def compress_public_key(public_key):
    """Compresses the public key to 33 bytes."""
    if public_key[-1] % 2 == 0:
        return b'\x02' + public_key[:32]
    else:
        return b'\x03' + public_key[:32]

def generate_private_key(context, queue, program, global_size=256):
    """Generate a private key using entropy gathered from OpenCL."""
    mem_block = np.random.randint(0, 2**64, size=global_size, dtype=np.uint64)

    # Generate random pixel data
    width, height = 256, 256  # Size of the random image
    pixel_data = np.random.randint(0, 256, size=(width * height), dtype=np.uint8)  # Random grayscale pixel data

    entropy = gather_entropy(context, queue, program, mem_block, pixel_data, global_size)
    entropy_bytes = entropy.tobytes()[:32]  # Truncate to 32 bytes

    # Display the entropy as a concatenated 32-byte hex string
    entropy_hex_string = entropy_bytes.hex()
    print(f"Entropy (hex): {entropy_hex_string}")
    
    private_key_bytes = double_sha256(context, queue, program, entropy_bytes)
    assert len(private_key_bytes) == 32, f"Private key length is {len(private_key_bytes)} instead of 32 bytes"
    
    # Clear sensitive data from memory
    mem_block.fill(0)
    entropy.fill(0)
    entropy_bytes = b'\x00' * len(entropy_bytes)

    return private_key_bytes

def generate_bitcoin_address_and_wif(private_key_bytes):
    """Generate Bitcoin address and WIF from a private key."""
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    vk = sk.get_verifying_key()
    compressed_public_key_bytes = compress_public_key(vk.to_string())

    sha256_hash = hashlib.sha256(compressed_public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    public_key_hash = ripemd160.digest()
    
    versioned_public_key = b'\x00' + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned_public_key).digest()).digest()[:4]
    address = base58.b58encode(versioned_public_key + checksum).decode('ascii')
    
    wif = generate_wif(private_key_bytes + b'\x01')  # Add \x01 to indicate a compressed key
    
    return address, wif

def verify_bitcoin_address_from_wif(wif):
    """Verify Bitcoin address obtained by importing the WIF."""
    imported_sk = ecdsa.SigningKey.from_string(base58.b58decode(wif)[1:-5], curve=SECP256k1)
    imported_vk = imported_sk.get_verifying_key()
    imported_public_key_bytes = compress_public_key(imported_vk.to_string())

    sha256_hash = hashlib.sha256(imported_public_key_bytes).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    public_key_hash = ripemd160.digest()

    versioned_public_key = b'\x00' + public_key_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned_public_key).digest()).digest()[:4]
    address = base58.b58encode(versioned_public_key + checksum).decode('ascii')
    
    return address

# Main execution
if __name__ == "__main__":
    try:
        # Initialize OpenCL context
        context, queue, device = create_opencl_context()

        # Compile the OpenCL kernel from file
        program = compile_kernel(context, "entropy_sha256.cl")

        # Generate private key
        private_key_bytes = generate_private_key(context, queue, program)

        # Generate Bitcoin address and WIF
        address, wif = generate_bitcoin_address_and_wif(private_key_bytes)

        # Output the results
        print(f"Private Key (hex): {private_key_bytes.hex()}")
        print(f"Bitcoin Address: {address}")
        print(f"WIF: {wif}")

        # Verify the generated address from the WIF
        imported_address = verify_bitcoin_address_from_wif(wif)
        assert address == imported_address, "Mismatch between the generated address and the address from the imported WIF"
        print("Address verification successful.")

    except cl.Error as cl_err:
        print(f"OpenCL error occurred: {cl_err}")
    except ecdsa.BadSignatureError:
        print("Signature verification failed.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        # Clean up OpenCL resources
        if 'queue' in locals():
            queue.finish()
        if 'context' in locals():
            del queue
            del context
        print("OpenCL resources have been successfully cleaned up.")
