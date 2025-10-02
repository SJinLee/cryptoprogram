import streamlit as st

# --- GF(2^8) 연산 ---

def gadd(a, b):
    """GF(2^8) 덧셈 (XOR)"""
    return a ^ b

def gmul(a, b):
    """GF(2^8) 곱셈"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high_bit_set = a & 0x80
        a <<= 1
        if high_bit_set:
            a ^= 0x1b  # AES의 기약 다항식 x^8 + x^4 + x^3 + x + 1 (0x11B)
        b >>= 1
    return p & 0xff

# --- SubBytes 연산 ---

# 미리 계산된 S-box와 Inverse S-box
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

def ginv(a):
    """GF(2^8) 곱셈 역원 계산"""
    if a == 0:
        return 0
    # 확장 유클리드 알고리즘 또는 페르마의 소정리 a^(254) 이용
    return pow(a, 254, 283) # 283은 0x11B

def affine_transform(b):
    """SubBytes의 Affine 변환"""
    c = 0x63
    return b ^ (b << 1 | b >> 7) & 0xff ^ (b << 2 | b >> 6) & 0xff ^ (b << 3 | b >> 5) & 0xff ^ (b << 4 | b >> 4) & 0xff ^ c

def sub_byte(b):
    """SubBytes 연산 (곱셈 역원 + Affine 변환)"""
    return S_BOX[b]

# --- ShiftRows 연산 ---

def state_to_matrix(state):
    """16바이트 리스트를 4x4 행렬로 변환 (열 우선)"""
    matrix = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            matrix[r][c] = state[c*4 + r]
    return matrix

def matrix_to_state(matrix):
    """4x4 행렬을 16바이트 리스트로 변환 (열 우선)"""
    state = [0]*16
    for r in range(4):
        for c in range(4):
            state[c*4 + r] = matrix[r][c]
    return state

def shift_rows(state_matrix):
    """ShiftRows 연산"""
    shifted_matrix = [row[:] for row in state_matrix]
    # 2번째 행: 왼쪽으로 1칸 shift
    shifted_matrix[1] = shifted_matrix[1][1:] + shifted_matrix[1][:1]
    # 3번째 행: 왼쪽으로 2칸 shift
    shifted_matrix[2] = shifted_matrix[2][2:] + shifted_matrix[2][:2]
    # 4번째 행: 왼쪽으로 3칸 shift
    shifted_matrix[3] = shifted_matrix[3][3:] + shifted_matrix[3][:3]
    return shifted_matrix

# --- MixColumns 연산 ---

def mix_columns(column):
    """MixColumns 연산 (한 개의 열에 대해)"""
    # 고정된 다항식: 02, 01, 01, 03 (역순으로)
    # 실제로는 02, 03, 01, 01 행렬과 곱함
    c = column
    return [
        gmul(c[0], 2) ^ gmul(c[1], 3) ^ gmul(c[2], 1) ^ gmul(c[3], 1),
        gmul(c[0], 1) ^ gmul(c[1], 2) ^ gmul(c[2], 3) ^ gmul(c[3], 1),
        gmul(c[0], 1) ^ gmul(c[1], 1) ^ gmul(c[2], 2) ^ gmul(c[3], 3),
        gmul(c[0], 3) ^ gmul(c[1], 1) ^ gmul(c[2], 1) ^ gmul(c[3], 2),
    ]

def mix_columns_poly_mult(column):
    """
    사용자가 요청한 특정 다항식 곱셈
    c(x) = c3*x^3 + c2*x^2 + c1*x + c0
    a(x) = 03*x^3 + 01*x^2 + 01*x + 02
    d(x) = a(x) * c(x) mod (x^4+1)
    """
    a = [0x02, 0x01, 0x01, 0x03] # a(x)의 계수
    c = column # c(x)의 계수
    
    d = [0] * 4
    
    for i in range(4):
        for j in range(4):
            # d_{i+j} = d_{i+j} + a_i * c_j
            # (x^4+1)로 나눈 나머지 -> x^4 = -1 = 1 (in GF(2))
            idx = (i + j) % 4
            d[idx] = gadd(d[idx], gmul(a[i], c[j]))
            
    return d

# --- Key Expansion ---

RCON = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
]

def sub_word(word):
    """Key Expansion의 SubWord 연산"""
    return [sub_byte(b) for b in word]

def rot_word(word):
    """Key Expansion의 RotWord 연산"""
    return word[1:] + word[:1]

def key_expansion(key, key_size=128):
    """주어진 키로부터 모든 라운드 키를 생성"""
    nk = key_size // 32
    nr = {128: 10, 192: 12, 256: 14}[key_size]

    # 키를 4바이트 워드 리스트로 변환
    w = [list(key[i:i+4]) for i in range(0, len(key), 4)]

    for i in range(nk, (nr + 1) * 4):
        temp = list(w[i-1]) # 이전 워드를 복사
        if i % nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] = temp[0] ^ RCON[i // nk]
        elif nk > 6 and i % nk == 4: # AES-256
            temp = sub_word(temp)
        
        # 이전 워드와 XOR하여 새 워드 생성
        prev_word = w[i-nk]
        new_word = [prev_word[j] ^ temp[j] for j in range(4)]
        w.append(new_word)
        
    # 생성된 워드들을 16바이트 라운드 키로 그룹화
    round_keys = []
    for i in range(nr + 1):
        round_key_words = w[i*4 : i*4 + 4]
        round_keys.append([byte for word in round_key_words for byte in word])
        
    return round_keys


# --- Encryption Process ---

def sub_bytes_state(state_matrix):
    return [[sub_byte(b) for b in row] for row in state_matrix]

def mix_columns_state(state_matrix):
    mixed = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state_matrix[r][c] for r in range(4)]
        mixed_col = mix_columns(col)
        for r in range(4):
            mixed[r][c] = mixed_col[r]
    return mixed

def add_round_key(state_matrix, round_key_matrix):
    return [[state_matrix[r][c] ^ round_key_matrix[r][c] for c in range(4)] for r in range(4)]

def encrypt_step_by_step(plaintext_bytes, key_bytes):
    """AES 암호화 과정을 단계별로 모두 기록하여 반환"""
    
    history = []
    nr = 10 # AES-128 기준

    # 1. 키 확장
    round_keys_bytes = key_expansion(key_bytes, 128)
    round_keys_matrix = [state_to_matrix(rk) for rk in round_keys_bytes]

    # 2. 초기 상태
    state = state_to_matrix(plaintext_bytes)
    history.append(("초기 상태", matrix_to_state(state)))

    # 3. Initial Round Key Addition
    state = add_round_key(state, round_keys_matrix[0])
    history.append(("AddRoundKey (Round 0)", matrix_to_state(state)))

    # 4. Main Rounds (1 to 9)
    for i in range(1, nr):
        round_history = []
        # SubBytes
        state = sub_bytes_state(state)
        round_history.append(("SubBytes", matrix_to_state(state)))
        # ShiftRows
        state = shift_rows(state)
        round_history.append(("ShiftRows", matrix_to_state(state)))
        # MixColumns
        state = mix_columns_state(state)
        round_history.append(("MixColumns", matrix_to_state(state)))
        # AddRoundKey
        state = add_round_key(state, round_keys_matrix[i])
        round_history.append(("AddRoundKey", matrix_to_state(state)))
        history.append((f"Round {i}", round_history))

    # 5. Final Round (10)
    final_round_history = []
    # SubBytes
    state = sub_bytes_state(state)
    final_round_history.append(("SubBytes", matrix_to_state(state)))
    # ShiftRows
    state = shift_rows(state)
    final_round_history.append(("ShiftRows", matrix_to_state(state)))
    # AddRoundKey
    state = add_round_key(state, round_keys_matrix[nr])
    final_round_history.append(("AddRoundKey", matrix_to_state(state)))
    history.append((f"Round {nr} (Final)", final_round_history))

    return history

def encrypt(plaintext_bytes, key_bytes):
    """Standard AES-128 encryption, returns final ciphertext."""
    history = encrypt_step_by_step(plaintext_bytes, key_bytes)
    return history[-1][1][-1][1] # Extracts the final ciphertext from the history

def count_bit_diff(bytes1, bytes2):
    """두 바이트 배열 간의 비트 차이 개수를 계산합니다."""
    diff_count = 0
    for b1, b2 in zip(bytes1, bytes2):
        xor_val = b1 ^ b2
        diff_count += bin(xor_val).count('1')
    return diff_count


# --- Decryption Process (Inverse Operations) ---

INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]

def inv_sub_byte(b):
    return INV_S_BOX[b]

def inv_sub_bytes_state(state_matrix):
    return [[inv_sub_byte(b) for b in row] for row in state_matrix]

def inv_shift_rows(state_matrix):
    shifted_matrix = [row[:] for row in state_matrix]
    # 2번째 행: 오른쪽으로 1칸 shift
    shifted_matrix[1] = shifted_matrix[1][-1:] + shifted_matrix[1][:-1]
    # 3번째 행: 오른쪽으로 2칸 shift
    shifted_matrix[2] = shifted_matrix[2][-2:] + shifted_matrix[2][:-2]
    # 4번째 행: 오른쪽으로 3칸 shift
    shifted_matrix[3] = shifted_matrix[3][-3:] + shifted_matrix[3][:-3]
    return shifted_matrix

def inv_mix_columns(column):
    c = column
    return [
        gmul(c[0], 0x0e) ^ gmul(c[1], 0x0b) ^ gmul(c[2], 0x0d) ^ gmul(c[3], 0x09),
        gmul(c[0], 0x09) ^ gmul(c[1], 0x0e) ^ gmul(c[2], 0x0b) ^ gmul(c[3], 0x0d),
        gmul(c[0], 0x0d) ^ gmul(c[1], 0x09) ^ gmul(c[2], 0x0e) ^ gmul(c[3], 0x0b),
        gmul(c[0], 0x0b) ^ gmul(c[1], 0x0d) ^ gmul(c[2], 0x09) ^ gmul(c[3], 0x0e),
    ]

def inv_mix_columns_state(state_matrix):
    mixed = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state_matrix[r][c] for r in range(4)]
        mixed_col = inv_mix_columns(col)
        for r in range(4):
            mixed[r][c] = mixed_col[r]
    return mixed

def decrypt(ciphertext_bytes, key_bytes):
    """Standard AES-128 decryption."""
    nr = 10 # AES-128 기준

    round_keys_bytes = key_expansion(key_bytes, 128)
    round_keys_matrix = [state_to_matrix(rk) for rk in round_keys_bytes]

    state = state_to_matrix(ciphertext_bytes)

    # Initial round
    state = add_round_key(state, round_keys_matrix[nr])

    # Main rounds (9 down to 1)
    for i in range(nr - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes_state(state)
        state = add_round_key(state, round_keys_matrix[i])
        state = inv_mix_columns_state(state)
    
    # Final round (0)
    state = inv_shift_rows(state)
    state = inv_sub_bytes_state(state)
    state = add_round_key(state, round_keys_matrix[0])

    return matrix_to_state(state)
