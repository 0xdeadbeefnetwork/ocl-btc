import os
import time
import pyopencl as cl
import numpy as np
from bit import Key

SAVE_FILE = 'last_btc_key.txt'
NUM_KEYS = 8192

def hex_to_wif(private_key_hex):
    key = Key.from_hex(private_key_hex)
    return key.to_wif()

def private_key_to_p2pkh(private_key_hex):
    key = Key.from_hex(private_key_hex)
    return key.address()  # Ensure this method is correct

def private_key_to_p2wpkh_p2sh(private_key_hex):
    key = Key.from_hex(private_key_hex)
    return key.p2wpkh_p2sh_address()  # Ensure this method is correct

def private_key_to_p2wpkh(private_key_hex):
    key = Key.from_hex(private_key_hex)
    return key.p2wpkh_address()  # Ensure this method is correct

def load_last_key():
    if os.path.exists(SAVE_FILE):
        with open(SAVE_FILE, 'r') as f:
            try:
                return int(f.read().strip(), 16)
            except ValueError:
                return 0
    return 0

def save_last_key(private_key_int):
    with open(SAVE_FILE, 'w') as f:
        f.write(f"{private_key_int:064x}")

def split_256bit_key(key):
    return (np.uint64(key >> 192), np.uint64((key >> 128) & 0xFFFFFFFFFFFFFFFF),
            np.uint64((key >> 64) & 0xFFFFFFFFFFFFFFFF), np.uint64(key & 0xFFFFFFFFFFFFFFFF))

def combine_256bit_key(key_parts):
    return (int(key_parts[0]) << 192) | (int(key_parts[1]) << 128) | (int(key_parts[2]) << 64) | int(key_parts[3])

def setup_opencl():
    try:
        platforms = cl.get_platforms()
        devices = platforms[0].get_devices(cl.device_type.GPU)
        if not devices:
            raise RuntimeError("No GPU devices found.")
        
        context = cl.Context([devices[0]])
        queue = cl.CommandQueue(context)

        kernel_code = """
        __kernel void increment_keys(__global ulong* keys_high, __global ulong* keys_mid1, 
                                     __global ulong* keys_mid2, __global ulong* keys_low) {
            int gid = get_global_id(0);
            keys_low[gid] += 1;
            if (keys_low[gid] == 0) {
                keys_mid2[gid] += 1;
                if (keys_mid2[gid] == 0) {
                    keys_mid1[gid] += 1;
                    if (keys_mid1[gid] == 0) {
                        keys_high[gid] += 1;
                    }
                }
            }
        }
        """

        program = cl.Program(context, kernel_code).build()
        kernel = cl.Kernel(program, "increment_keys")
        local_size = kernel.get_work_group_info(cl.kernel_work_group_info.PREFERRED_WORK_GROUP_SIZE_MULTIPLE, devices[0])

        return context, queue, program, local_size
    
    except cl.Error as e:
        print(f"OpenCL error: {e}")
        raise

    except Exception as e:
        print(f"General error: {e}")
        raise

def generate_private_keys(start_value, num_keys=NUM_KEYS):
    max_value = 2**256 - 1
    start_key_parts = split_256bit_key(start_value)

    context, queue, program, local_size = setup_opencl()

    keys_high = np.full(num_keys, start_key_parts[0], dtype=np.uint64)
    keys_mid1 = np.full(num_keys, start_key_parts[1], dtype=np.uint64)
    keys_mid2 = np.full(num_keys, start_key_parts[2], dtype=np.uint64)
    keys_low = np.array([start_key_parts[3] + i for i in range(num_keys)], dtype=np.uint64)

    buffer_high = cl.Buffer(context, cl.mem_flags.READ_WRITE | cl.mem_flags.COPY_HOST_PTR, hostbuf=keys_high)
    buffer_mid1 = cl.Buffer(context, cl.mem_flags.READ_WRITE | cl.mem_flags.COPY_HOST_PTR, hostbuf=keys_mid1)
    buffer_mid2 = cl.Buffer(context, cl.mem_flags.READ_WRITE | cl.mem_flags.COPY_HOST_PTR, hostbuf=keys_mid2)
    buffer_low = cl.Buffer(context, cl.mem_flags.READ_WRITE | cl.mem_flags.COPY_HOST_PTR, hostbuf=keys_low)

    processed_keys = set()

    try:
        while True:
            global_size = (num_keys,)
            program.increment_keys(queue, global_size, (local_size,), buffer_high, buffer_mid1, buffer_mid2, buffer_low)
            
            cl.enqueue_copy(queue, keys_high, buffer_high).wait()
            cl.enqueue_copy(queue, keys_mid1, buffer_mid1).wait()
            cl.enqueue_copy(queue, keys_mid2, buffer_mid2).wait()
            cl.enqueue_copy(queue, keys_low, buffer_low).wait()

            new_keys = []

            for i in range(num_keys):
                private_key_parts = (keys_high[i], keys_mid1[i], keys_mid2[i], keys_low[i])
                private_key_int = combine_256bit_key(private_key_parts)

                if private_key_int > max_value:
                    private_key_int = 0

                private_key_hex = f"{private_key_int:064x}"
                if private_key_hex in processed_keys:
                    continue

                processed_keys.add(private_key_hex)
                new_keys.append((private_key_hex, private_key_int))

            for private_key_hex, private_key_int in new_keys:
                try:
                    wif_key = hex_to_wif(private_key_hex)
                    p2pkh_address = private_key_to_p2pkh(private_key_hex)
                    p2wpkh_p2sh_address = private_key_to_p2wpkh_p2sh(private_key_hex)
                    p2wpkh_address = private_key_to_p2wpkh(private_key_hex)

                    # Print private key in Electrum-compatible format
                    print(f"Private Key (p2pkh): p2pkh:{wif_key}")
                    print(f"Address (p2pkh): {p2pkh_address}")
                    print(f"Private Key (p2wpkh-p2sh): p2wpkh-p2sh:{wif_key}")
                    print(f"Address (p2wpkh-p2sh): {p2wpkh_p2sh_address}")
                    print(f"Private Key (p2wpkh): p2wpkh:{wif_key}")
                    print(f"Address (p2wpkh): {p2wpkh_address}")
                    print("-" * 80)

                except ValueError:
                    pass

    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting...")

    finally:
        save_last_key(combine_256bit_key((keys_high[-1], keys_mid1[-1], keys_mid2[-1], keys_low[-1])))

def main():
    start_value = load_last_key()
    generate_private_keys(start_value)

if __name__ == "__main__":
    main()
