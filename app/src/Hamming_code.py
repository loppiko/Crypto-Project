import numpy as np
import random

#encryptor functions
from Encryptor import readBin, saveBin, readJson



# ------ Hamming codes ------

def encode_hamming_code_4_into_7(bin_0_1_blocks: list[list[bytes]], error_function: list[bytes] = None) -> list[list[bytes]]:
    if (not np.all(list(map(lambda block: True if len(block) == 4 else False, bin_0_1_blocks)))):
        raise ValueError("Data is not in 4-bit blocks")

    encoded_data = []

    G = ([
        [1, 1, 1, 0, 0, 0, 0],
        [1, 0, 0, 1, 1, 0, 0],
        [0, 1, 0, 1, 0, 1, 0],
        [1, 1, 0, 1, 0, 0, 1],
    ])

    for block in bin_0_1_blocks:
        simple_block = np.dot(np.array(block), np.array(G)) % 2

        if (error_function is None): encoded_data.append(simple_block)
        else: encoded_data.append(error_function(simple_block))

    return encoded_data



def decode_hamming_code_4_into_7(hamming_data: list[list[bytes]]) -> list[list[bytes]]:

    def calculate_parity_bits(block):
        return [
            (block[2] ^ block[4] ^ block[6]),
            (block[2] ^ block[5] ^ block[6]),
            (block[4] ^ block[5] ^ block[6])
        ]

    recovered_data = []
    
    total_errors = 0
    corrected_errors = 0

    H = np.array([
        [0, 0, 1],
        [0, 1, 0],
        [0, 1, 1],
        [1, 0, 0],
        [1, 0, 1],
        [1, 1, 0],
        [1, 1, 1]
        ])

    P1_INDEX, P2_INDEX, P4_INDEX = 0, 1, 3


    for block in hamming_data:
        corrected_block = block

        new_parity_bits = calculate_parity_bits(block)

        old_parity_bits = [
            block[P1_INDEX],
            block[P2_INDEX],
            block[P4_INDEX]
        ]

        if (new_parity_bits != old_parity_bits):
            total_errors += 1
            error_index_bin = (np.dot(np.array(corrected_block), H)) % 2
            error_index = int(''.join(map(str, error_index_bin)), 2) - 1


            corrected_block[error_index] = (1 - block[error_index])
            
            if (int(''.join(map(str, (np.dot(np.array(corrected_block), H) % 2))), 2) == 0): corrected_errors += 1


        recovered_data.append(corrected_block)

    unrecoverable_errors = total_errors - corrected_errors
    if (unrecoverable_errors > 0): print("\n--- OUTPUT FILE CONTAINS ERRORS ---")
    print(f"\nCorrected error statistic: \n\tCorrected: {corrected_errors}\n\tUnrecoverable: {unrecoverable_errors}\n")


    original_mes = list(map(lambda block: [block[2], block[4], block[5], block[6]], recovered_data))

    return original_mes


# ------ Binary functions ------

def binary_into_0_and_1(bin: bytes) -> bytes:           # b'a' -> '0010110'
    bin_0_1 = ''.join(format(asciiNum, '08b') for asciiNum in bin)
    return bin_0_1


def divide_into_bit_blocks(bin_0_1: bytes, block_length: int) -> list[list[bytes]]:         # '1011101011...' -> [[1, 0, 1, 1], ...]
    res = [bin_0_1[i:i + block_length] for i in range(0, len(bin_0_1), block_length)]
    return list(map(lambda string: list(map(lambda char: int(char), string)), res))

def merge_4_bit_blocks_into_8_bits(bin_0_1_blocks: list[list[bytes]]) -> list[bytes]:      # [[1,1,0,0],[0,1,1,1]] -> ['11000111']
    original_mes = []
    for i in range(0, len(bin_0_1_blocks), 2):
        original_mes.append(["".join(map(str, bin_0_1_blocks[i])) + "".join(map(str, bin_0_1_blocks[i + 1]))])
    
    return np.array(original_mes).flatten()


def encourage_error_function(block):
    # Error can occur only once on 1 block
    potential_index_errors = [elem for elem in range(0, 7)]
    error_index = potential_index_errors[random.randint(0, len(potential_index_errors) - 1)]
    block[error_index] = 1 - block[error_index]
    return block
    




if __name__ == "__main__":
    config = readJson("config.json")

    keysFolderSource = config["keys_folder_source"]
    fileToEncrypt = config["file_to_encrypt"]
    signaturesFile = config["signatures_file"]



    input_data = readBin(fileToEncrypt)
    bin_0_1 = binary_into_0_and_1(input_data)

    bin_0_1_blocks = divide_into_bit_blocks(bin_0_1, 4)


    hamming_code = encode_hamming_code_4_into_7(bin_0_1_blocks, encourage_error_function)
    bin_0_1_blocks = decode_hamming_code_4_into_7(hamming_code)

    output_8_bits = merge_4_bit_blocks_into_8_bits(bin_0_1_blocks)


    byte_data = bytes([int(block, 2) for block in output_8_bits])
    saveBin(byte_data, fileToEncrypt)