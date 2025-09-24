'''
Core DES (Data Encryption Standard) algorithm logic.
'''

# --- Helper functions ---

def permute(block, table):
    """Applies a permutation table to a block."""
    return [block[i - 1] for i in table]

def xor(a, b):
    """XORs two lists of bits."""
    return [x ^ y for x, y in zip(a, b)]

def bin_to_dec(binary_list):
    """Converts a list of bits to a decimal number."""
    return int("".join(map(str, binary_list)), 2)

def dec_to_bin(decimal, num_bits):
    """Converts a decimal number to a list of bits."""
    return [int(b) for b in bin(decimal)[2:].zfill(num_bits)]

# --- Constants for DES Key Schedule ---

PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# --- Constants for DES Encryption/Decryption ---

IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
]

E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
]

S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

P = [ 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 ]

FP = [ 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 ]

def s_box_substitution(xored_block):
    """Performs the S-Box substitution on a 48-bit block."""
    sbox_output = []
    for i in range(8):
        chunk = xored_block[i*6 : (i+1)*6]
        row = bin_to_dec([chunk[0], chunk[5]])
        col = bin_to_dec(chunk[1:5])
        sbox_val = S_BOXES[i][row][col]
        sbox_output.extend(dec_to_bin(sbox_val, 4))
    return sbox_output

def feistel_function(block, round_key):
    """The Feistel function (f-function) of DES."""
    # 1. Expansion
    expanded_block = permute(block, E)
    # 2. XOR with round key
    xored_block = xor(expanded_block, round_key)
    # 3. S-Box substitution
    sbox_output = s_box_substitution(xored_block)
    # 4. P-Box permutation
    return permute(sbox_output, P)

def generate_round_keys(key_str):
    '''Generates the 16 round keys from the initial 64-bit key string.'''
    key_bits = [int(b) for b in key_str]
    permuted_key_56 = permute(key_bits, PC1)
    c_block = permuted_key_56[:28]
    d_block = permuted_key_56[28:]
    round_keys = []
    for i in range(16):
        shift_amount = SHIFTS[i]
        c_block = c_block[shift_amount:] + c_block[:shift_amount]
        d_block = d_block[shift_amount:] + d_block[:shift_amount]
        combined_block = c_block + d_block
        round_key = permute(combined_block, PC2)
        round_keys.append(round_key)
    return round_keys

def process_block(block_str, round_keys, is_encrypt=True):
    """Processes a single 64-bit block for either encryption or decryption."""
    block = [int(b) for b in block_str]
    permuted_block = permute(block, IP)
    left, right = permuted_block[:32], permuted_block[32:]

    keys = round_keys if is_encrypt else round_keys[::-1]
    
    round_logs = []

    for i, round_key in enumerate(keys):
        l_prev = left
        left = right
        f_result = feistel_function(right, round_key)
        right = xor(l_prev, f_result)
        
        round_logs.append({
            'round': i + 1,
            'left': "".join(map(str, left)),
            'right': "".join(map(str, right)),
            'round_key': "".join(map(str, round_key))
        })

    # Final swap
    final_block = right + left
    result_bits = permute(final_block, FP)
    return result_bits, round_logs

def encrypt(plaintext_str, round_keys):
    '''Encrypts a 64-bit plaintext string and returns ciphertext and logs.'''
    result_bits, round_logs = process_block(plaintext_str, round_keys, is_encrypt=True)
    ciphertext = "".join(map(str, result_bits))
    return ciphertext, round_logs

def decrypt(ciphertext_str, round_keys):
    '''Decrypts a 64-bit ciphertext string.'''
    result_bits, _ = process_block(ciphertext_str, round_keys, is_encrypt=False)
    return "".join(map(str, result_bits))