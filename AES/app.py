import streamlit as st
import aes_utils as utils

# 페이지 기본 설정
st.set_page_config(layout="wide")

# --- 상태 관리 ---
if 'key_size' not in st.session_state:
    st.session_state.key_size = 128

def reset_pages():
    # TODO: 각 페이지의 상태를 초기화하는 로직 추가
    pass

# --- 상단 키 사이즈 선택 ---
st.subheader("AES 키 길이 선택")
selected_key_size = st.radio(
    "AES Key Size",
    [128, 192, 256],
    index=0,
    horizontal=True,
    label_visibility="collapsed"
)

if st.session_state.key_size != selected_key_size:
    st.session_state.key_size = selected_key_size
    reset_pages()
    st.rerun()

st.markdown("---")

# --- Helper function to format matrix ---
def format_matrix(matrix):
    return "\n".join([" ".join([f"{byte:02x}" for byte in row]) for row in matrix])

# --- 메인 레이아웃 ---
col1, col2 = st.columns([1, 1])

with col1:
    st.header("페이지")
    tab_names = [
        "AES 소개",
        "주요 연산 과정",
        "라운드 키 생성",
        "라운드별 암호화",
        "쇄도 효과",
        "암호 해독",
        "다른 공격 기법",
        "기타 정보"
    ]
    
    page_tabs = st.tabs(tab_names)

    with page_tabs[0]:
        st.subheader("AES (Advanced Encryption Standard) 소개")
        st.markdown("""
        AES는 ‘Advanced Encryption Standard’의 약자로, 2001년 미국 국립표준기술연구소(NIST)에 의해 연방 정보 처리 표준(FIPS 197)으로 지정된 대칭키 암호화 알고리즘입니다.
        기존의 데이터 암호화 표준이었던 DES(Data Encryption Standard)를 대체하기 위해 만들어졌습니다.

        AES는 벨기에의 암호학자 Joan Daemen과 Vincent Rijmen이 개발한 **Rijndael(레인달)** 알고리즘에 기반하고 있으며, 전 세계적으로 가장 널리 사용되는 암호화 표준 중 하나입니다.

        #### 주요 특징
        - **대칭키 암호:** 암호화와 복호화에 동일한 키를 사용합니다.
        - **블록 암호:** 고정된 크기(128비트)의 데이터 블록을 단위로 암호화를 수행합니다.
        - **다양한 키 길이:** 128, 192, 256비트 중 하나의 키 길이를 선택할 수 있으며, 키 길이에 따라 라운드 수가 달라집니다.
            - **AES-128:** 10 라운드
            - **AES-192:** 12 라운드
            - **AES-256:** 14 라운드
        - **SPN 구조:** Subsitution-Permutation Network 구조를 기반으로 하여 혼돈(Confusion)과 확산(Diffusion) 속성을 효과적으로 만족시킵니다.
        """)

    with page_tabs[1]:
        st.subheader("주요 연산 과정")
        st.markdown("AES는 각 라운드에서 4가지 주요 연산을 반복적으로 수행합니다. (마지막 라운드는 MixColumns 제외)")

        st.markdown("#### 1. SubBytes (치환 연산)")
        st.markdown("SubBytes는 State의 각 바이트를 S-Box(Substitution Box)라는 정해진 표를 이용해 새로운 바이트로 치환하는 과정입니다. 이 비선형(non-linear) 연산은 암호의 **혼돈(Confusion)** 속성을 제공하여, 키와 암호문의 관계를 복잡하게 만듭니다.")
        st.markdown("연산 과정은 다음과 같습니다.")
        st.markdown("1. State의 각 바이트에 대해 GF(2^8) 상에서의 곱셈 역원을 구합니다. (0x00은 0x00으로 매핑)")
        st.markdown("2. 곱셈 역원을 구한 값에 대해 아래와 같은 Affine 변환을 적용합니다.")
        st.latex(r''' b_i' = b_i \oplus b_{(i+4) \pmod 8} \oplus b_{(i+5) \pmod 8} \oplus b_{(i+6) \pmod 8} \oplus b_{(i+7) \pmod 8} \oplus c_i ''')
        st.markdown("오른쪽의 **SubBytes 계산기**에서 직접 값을 입력하여 결과를 확인할 수 있습니다.")

        st.markdown("--- ")
        st.markdown("#### 2. ShiftRows (행 이동 연산)")
        st.markdown("ShiftRows는 State의 각 행을 정해진 규칙에 따라 왼쪽으로 순환 이동(Cyclic Shift)시키는 과정입니다. 이 연산은 암호의 **확산(Diffusion)** 속성을 제공하여, 한 평문 블록의 여러 비트가 암호문의 여러 비트에 영향을 주도록 합니다.")
        st.markdown("- 첫 번째 행: 이동하지 않음")
        st.markdown("- 두 번째 행: 왼쪽으로 1바이트 이동")
        st.markdown("- 세 번째 행: 왼쪽으로 2바이트 이동")
        st.markdown("- 네 번째 행: 왼쪽으로 3바이트 이동")
        st.code("""
        [S00 S01 S02 S03]      [S00 S01 S02 S03]
        [S10 S11 S12 S13]  ->  [S11 S12 S13 S10]
        [S20 S21 S22 S23]  ->  [S22 S23 S20 S21]
        [S30 S31 S32 S33]  ->  [S33 S30 S31 S32]
        """, language='text')
        st.markdown("오른쪽의 **ShiftRows 계산기**에서 직접 값을 입력하여 결과를 확인할 수 있습니다.")

        st.markdown("--- ")
        st.markdown("#### 3. MixColumns (열 섞기 연산)")
        st.markdown("MixColumns는 State의 각 열을 GF(2^8) 상에서 정해진 행렬과 곱하는 연산입니다. ShiftRows와 마찬가지로 **확산(Diffusion)** 속성을 강화하며, 한 열 안의 바이트들이 서로 영향을 주게 만듭니다.")
        st.markdown("각 열은 아래와 같은 행렬 곱셈을 통해 변환됩니다.")
        st.latex(r'''
        \begin{bmatrix} s'_{0,c} \\ s'_{1,c} \\ s'_{2,c} \\ s'_{3,c} \end{bmatrix} = 
        \begin{bmatrix} 02 & 03 & 01 & 01 \\ 01 & 02 & 03 & 01 \\ 01 & 01 & 02 & 03 \\ 03 & 01 & 01 & 02 \end{bmatrix}
        \begin{bmatrix} s_{0,c} \\ s_{1,c} \\ s_{2,c} \\ s_{3,c} \end{bmatrix}
        ''')
        st.markdown("오른쪽의 **MixColumns 다항식 곱셈 계산기**에서 열 벡터와 특정 다항식의 곱셈 결과를 확인할 수 있습니다.")

        st.markdown("--- ")
        st.markdown("#### 4. AddRoundKey (라운드 키 덧셈)")
        st.markdown("AddRoundKey는 State와 현재 라운드에 해당하는 라운드 키를 XOR(GF(2^8)에서의 덧셈)하는 연산입니다. 이 과정은 키를 암호문에 직접적으로 혼합하는 유일한 단계입니다.")
        st.code("State = State XOR RoundKey", language='text')


    with page_tabs[2]:
        st.subheader("라운드 키 생성 (Key Expansion)")
        st.markdown("AES는 암호화의 각 라운드마다 다른 키를 사용하는데, 이 라운드 키들은 최초의 비밀 키(Cipher Key)로부터 **키 확장(Key Expansion)** 이라는 과정을 통해 생성됩니다.")
        st.markdown("현재 선택된 키 길이는 **{st.session_state.key_size}비트** 입니다.")

        st.markdown("#### 키 확장 과정 (AES-128 기준)")
        st.markdown("1. 128비트(16바이트) 비밀 키는 4개의 32비트(4바이트) 워드(w0, w1, w2, w3)로 나뉩니다.")
        st.markdown("2. 이후의 워드들(w4 ~ w43)은 이전 워드들을 기반으로 순차적으로 생성됩니다.")
        st.markdown("3. 4의 배수가 되는 인덱스의 워드(w4, w8, w12, ...)를 생성할 때는 특별한 연산이 추가됩니다.")
        st.code("""
        temp = w[i-1]
        if i % 4 == 0:
            temp = SubWord(RotWord(temp)) ^ Rcon[i/4]
        w[i] = w[i-4] ^ temp
        """, language='c')
        st.markdown("- **RotWord**: 워드의 바이트들을 왼쪽으로 한 칸씩 순환 이동시킵니다. `[b0, b1, b2, b3]` -> `[b1, b2, b3, b0]`")
        st.markdown("- **SubWord**: 워드의 각 바이트를 S-Box를 이용해 치환합니다.")
        st.markdown("- **Rcon**: 라운드 상수(Round Constant)와 XOR 연산을 수행합니다. 라운드마다 다른 값을 사용하여 대칭성을 깨뜨립니다.")

        st.markdown("--- ")
        st.markdown("#### 라운드 키 생성 실습")
        st.write("16진수 16바이트(32글자) 키를 입력하고 버튼을 누르면 모든 라운드 키가 생성됩니다.")
        
        default_key = "2b7e151628aed2a6abf7158809cf4f3c"
        key_hex = st.text_input("비밀 키 (32 Hex chars)", default_key)

        if st.button("라운드 키 생성"):
            try:
                if len(key_hex) != 32:
                    raise ValueError("키는 정확히 32개의 16진수 문자여야 합니다.")
                key_bytes = [int(key_hex[i:i+2], 16) for i in range(0, 32, 2)]
                
                round_keys = utils.key_expansion(key_bytes, 128) # 현재는 128비트만 지원

                st.success("**11개의 라운드 키가 생성되었습니다.**")
                for i, rk in enumerate(round_keys):
                    st.markdown(f"**Round {i}**")
                    st.code(format_matrix(utils.state_to_matrix(rk)), language='text')

            except ValueError as e:
                st.error(f"입력 오류: {e}")

    with page_tabs[3]:
        st.subheader("라운드별 암호화 결과")
        st.markdown("평문과 비밀 키(각 16바이트)를 입력하면 전체 암호화 과정의 각 단계별 결과를 확인할 수 있습니다.")

        default_plaintext = "3243f6a8885a308d313198a2e0370734"
        default_key = "2b7e151628aed2a6abf7158809cf4f3c"

        pt_hex = st.text_input("평문 (32 Hex chars)", default_plaintext)
        key_hex_enc = st.text_input("비밀 키 (32 Hex chars) ", default_key, key="encryption_key")

        if st.button("암호화 과정 보기"):
            try:
                if len(pt_hex) != 32 or len(key_hex_enc) != 32:
                    raise ValueError("평문과 키는 정확히 32개의 16진수 문자여야 합니다.")
                
                pt_bytes = [int(pt_hex[i:i+2], 16) for i in range(0, 32, 2)]
                key_bytes = [int(key_hex_enc[i:i+2], 16) for i in range(0, 32, 2)]

                history = utils.encrypt_step_by_step(pt_bytes, key_bytes)

                st.success("암호화 과정 전체 결과")

                for item in history:
                    title, content = item
                    if isinstance(content, list) and isinstance(content[0], tuple):
                        # Main rounds and final round
                        with st.expander(f"**{title}**"):
                            for step_name, step_state in content:
                                st.markdown(f"**{step_name} 후 State:**")
                                st.code(format_matrix(utils.state_to_matrix(step_state)), language='text')
                    else:
                        # Initial state and pre-round
                        st.markdown(f"### {title}")
                        st.code(format_matrix(utils.state_to_matrix(content)), language='text')
                
                final_ciphertext = history[-1][1][-1][1]
                st.markdown("### 최종 암호문")
                st.code("".join([f"{b:02x}" for b in final_ciphertext]))

            except ValueError as e:
                st.error(f"입력 오류: {e}")
    with page_tabs[4]:
        st.subheader("쇄도 효과 (Avalanche Effect)")
        st.markdown("""
        쇄도 효과는 암호학에서 아주 중요한 속성으로, 입력값(평문 또는 키)의 아주 작은 변화(예: 단 1비트의 변경)가 출력값(암호문)에 매우 큰 변화(이상적으로는 약 50%의 비트가 변경)를 일으키는 현상을 말합니다.
        
        이 효과는 평문과 암호문 사이의 관계를 예측하기 어렵게 만들어, 암호 분석을 훨씬 더 복잡하게 만듭니다. AES는 이 쇄도 효과가 매우 강력하게 나타나는 알고리즘입니다.
        
        아래에서 평문의 특정 비트 하나를 변경했을 때, 암호문이 얼마나 크게 변하는지 직접 확인해 보세요.
        """)

        default_plaintext_av = "3243f6a8885a308d313198a2e0370734"
        default_key_av = "2b7e151628aed2a6abf7158809cf4f3c"

        pt_hex_av = st.text_input("평문 (32 Hex chars)", default_plaintext_av, key="avalanche_pt")
        key_hex_av = st.text_input("비밀 키 (32 Hex chars)", default_key_av, key="avalanche_key")
        bit_to_flip = st.number_input("변경할 비트 위치 (0-127)", min_value=0, max_value=127, value=64)

        if st.button("쇄도 효과 확인"):
            try:
                if len(pt_hex_av) != 32 or len(key_hex_av) != 32:
                    raise ValueError("평문과 키는 정확히 32개의 16진수 문자여야 합니다.")
                
                pt_bytes_orig = [int(pt_hex_av[i:i+2], 16) for i in range(0, 32, 2)]
                key_bytes_av = [int(key_hex_av[i:i+2], 16) for i in range(0, 32, 2)]

                # 원본 암호화
                ct_bytes_orig = utils.encrypt(pt_bytes_orig, key_bytes_av)

                # 평문 1비트 변경
                pt_bytes_mod = list(pt_bytes_orig)
                byte_index = bit_to_flip // 8
                bit_index_in_byte = 7 - (bit_to_flip % 8)
                pt_bytes_mod[byte_index] ^= (1 << bit_index_in_byte)
                pt_bytes_mod = bytes(pt_bytes_mod)

                # 변경된 평문 암호화
                ct_bytes_mod = utils.encrypt(pt_bytes_mod, key_bytes_av)

                # 결과 비교
                bit_diff = utils.count_bit_diff(ct_bytes_orig, ct_bytes_mod)
                diff_percentage = (bit_diff / 128) * 100

                st.markdown("**원본 평문**")
                st.code("".join(f"{b:02x}" for b in pt_bytes_orig))
                st.markdown("**-> 원본 암호문**")
                st.code("".join(f"{b:02x}" for b in ct_bytes_orig))
                st.markdown("---")
                st.markdown(f"**변경된 평문 ({bit_to_flip}번 비트 변경)**")
                st.code("".join(f"{b:02x}" for b in pt_bytes_mod))
                st.markdown("**-> 변경된 암호문**")
                st.code("".join(f"{b:02x}" for b in ct_bytes_mod))
                st.markdown("---")
                st.success(f"**결과: 두 암호문은 총 {bit_diff}개의 비트가 다르며, 이는 {diff_percentage:.2f}%의 차이입니다.**")

            except ValueError as e:
                st.error(f"입력 오류: {e}")
    with page_tabs[5]:
        st.subheader("Brute Force 공격 시뮬레이션")
        st.markdown("""
        Brute Force(무차별 대입) 공격은 가능한 모든 키를 하나씩 시도하여 올바른 키를 찾는 가장 단순하지만 강력한 공격 방법입니다. 
        하지만 AES-128의 키 경우의 수는 2^128 (약 3.4 x 10^38)으로, 현재 기술로는 사실상 해독이 불가능합니다.
        
        여기서는 공격의 원리를 보여주기 위해, **키의 마지막 1~2 바이트만 모른다고 가정**하고 해당 부분만 무차별 대입하여 원래 키를 찾아내는 과정을 시뮬레이션합니다.
        """)

        default_ciphertext_bf = "3925841d02dc09fbdc118597196a0b32" # pt/key default로 암호화한 결과
        default_plaintext_bf = "3243f6a8885a308d313198a2e0370734"
        default_key_bf = "2b7e151628aed2a6abf7158809cf4f"

        ct_hex_bf = st.text_input("암호문 (32 Hex chars)", default_ciphertext_bf, key="bf_ct")
        pt_hex_bf = st.text_input("알고 있는 평문 (32 Hex chars)", default_plaintext_bf, key="bf_pt")
        
        bytes_to_bruteforce = st.radio("Brute-force 할 바이트 수", [1, 2], index=1, horizontal=True)
        
        # 전체 기본 키
        default_key_full = "2b7e151628aed2a6abf7158809cf4f3c"

        if bytes_to_bruteforce == 1:
            known_bytes_len = 15
            key_end = "XX"
            search_space = 2**8 # 256
        else: # 2 bytes
            known_bytes_len = 14
            key_end = "XXXX"
            search_space = 2**16 # 65536

        default_known_key_part = default_key_full[:known_bytes_len*2]

        # 라디오 버튼이 바뀔 때마다 text_input을 새로 그리기 위해 동적 key 사용
        text_input_key = f"bf_key_{bytes_to_bruteforce}"
        key_hex_bf_known = st.text_input(f"알고 있는 키 부분 ({known_bytes_len*2} Hex chars)", default_known_key_part, key=text_input_key)
        st.markdown(f"시도할 키 형식: `{key_hex_bf_known + key_end}`")

        if st.button("Brute Force 공격 시작"):
            try:
                if len(ct_hex_bf)!=32 or len(pt_hex_bf)!=32 or len(key_hex_bf_known)!=(known_bytes_len*2):
                    raise ValueError("입력 길이를 확인하세요.")

                ct_bytes = bytes.fromhex(ct_hex_bf)
                pt_bytes_known = bytes.fromhex(pt_hex_bf)
                key_bytes_known = bytes.fromhex(key_hex_bf_known)

                st.info(f"총 {search_space}개의 키를 테스트합니다...")
                progress_bar = st.progress(0)
                status_text = st.empty()
                found = False

                for i in range(search_space):
                    if bytes_to_bruteforce == 1:
                        candidate_key_bytes = key_bytes_known + bytes([i])
                    else: # 2 bytes
                        candidate_key_bytes = key_bytes_known + i.to_bytes(2, 'big')
                    
                    decrypted_bytes = utils.decrypt(ct_bytes, candidate_key_bytes)

                    # UI 업데이트를 너무 자주 하지 않도록 조절
                    if i % 256 == 0 or bytes_to_bruteforce == 1:
                        progress = (i + 1) / search_space
                        progress_bar.progress(progress)
                        status_text.text(f"시도 중 ({i+1}/{search_space}): {candidate_key_bytes.hex()}")

                    if bytes(decrypted_bytes) == pt_bytes_known:
                        found = True
                        break
                
                progress_bar.empty()
                status_text.empty()
                if found:
                    st.success(f"**성공!** {i+1}번의 시도 끝에 키를 찾았습니다.")
                    st.markdown(f"**찾은 전체 키:** `{candidate_key_bytes.hex()}`")
                else:
                    st.error("**실패.** 모든 키를 시도했지만 일치하는 키를 찾지 못했습니다.")

            except ValueError as e:
                st.error(f"입력 오류: {e}")
    with page_tabs[6]:
        st.subheader("다른 알려진 암호 해독 방법")
        st.markdown("""
        Brute-force 공격 외에도 암호 알고리즘을 분석하기 위한 다양한 기법이 존재합니다. AES는 이러한 공격들에 대해 높은 안전성을 갖도록 설계되었습니다.
        """)
        st.markdown("#### 차분 분석 (Differential Cryptanalysis)")
        st.markdown("입력값의 차이(Difference)가 출력값의 차이에 어떤 영향을 미치는지 통계적으로 분석하는 기법입니다. 특정 입력 차이가 특정 출력 차이를 높은 확률로 유발한다면, 이를 이용해 키를 추측할 수 있습니다. AES의 S-Box와 MixColumns 연산은 이러한 차분 특성이 전파되는 것을 효과적으로 막도록 설계되었습니다.")

        st.markdown("#### 선형 분석 (Linear Cryptanalysis)")
        st.markdown("평문, 암호문, 키 비트들 간에 성립하는 근사적인 선형 관계식(Linear Approximation)을 찾아내어 키를 분석하는 기법입니다. 많은 평문-암호문 쌍을 필요로 하며, AES는 선형 관계가 나타날 확률을 매우 낮게 만들어 방어합니다.")

        st.markdown("#### 사이드 채널 공격 (Side-Channel Attacks)")
        st.markdown("알고리즘의 수학적 취약점이 아닌, 알고리즘이 동작하는 물리적 환경에서 부수적으로 발생하는 정보(Side Channel)를 이용하는 공격입니다. 이는 소프트웨어나 하드웨어 구현의 취약점을 파고듭니다.")
        st.markdown("- **시간 공격 (Timing Attack):** 연산에 걸리는 시간 차이를 분석하여 키를 추측합니다.")
        st.markdown("- **전력 분석 공격 (Power Analysis Attack):** 암호화 장비가 소모하는 전력량의 변화를 분석합니다.")
        st.markdown("- **음향 공격 (Acoustic Attack):** 컴퓨터가 연산 시 내는 미세한 소리를 분석합니다.")

        st.markdown("#### 관련키 공격 (Related-Key Attack)")
        st.markdown("공격자가 선택한 특정 관계를 갖는 여러 키들로 암호화된 암호문을 얻을 수 있을 때 가능한 공격입니다. AES는 키 확장(Key Expansion) 과정의 비선형성 때문에 관련키 공격에 대해서도 강한 내성을 가집니다.")
        
    with page_tabs[7]:
        st.subheader("기타 정보")
        st.markdown("#### AES-NI (Advanced Encryption Standard New Instructions)")
        st.markdown("AES-NI는 최신 CPU에 포함된 특별한 명령어 셋(Instruction Set)입니다. AES 암호화 및 복호화 연산을 하드웨어 수준에서 직접 지원하여, 소프트웨어로만 구현했을 때보다 훨씬 빠르고 안전하게 AES를 실행할 수 있게 해줍니다. 오늘날 대부분의 웹 트래픽(HTTPS/TLS) 암호화는 이 하드웨어 가속 기능 덕분에 매우 효율적으로 처리됩니다.")

        st.markdown("#### 양자내성암호 (Post-Quantum Cryptography, PQC)")
        st.markdown("현재의 공개키 암호(RSA, ECC 등)는 미래에 등장할 대규모 양자 컴퓨터에 의해 쉽게 해독될 수 있습니다. 하지만 AES와 같은 대칭키 암호는 양자 컴퓨터에 대해서도 상대적으로 안전하며, 키 길이를 256비트로 늘리는 것만으로도 충분한 방어력을 가질 것으로 여겨집니다. 그럼에도 불구하고, 미국 NIST를 중심으로 양자 컴퓨터의 위협에 대응하기 위한 새로운 암호 표준(양자내성암호)을 수립하는 작업이 활발히 진행되고 있습니다.")

        st.markdown("#### 블록 암호 운용 방식 (Block Cipher Modes of Operation)")
        st.markdown("AES는 16바이트(128비트)의 고정된 블록 단위로 동작합니다. 따라서 16바이트보다 긴 메시지를 암호화하려면 블록들을 어떻게 연결하여 처리할지에 대한 규칙이 필요한데, 이를 '운용 방식'이라고 합니다. 단순한 ECB 방식부터 CBC, CTR, 그리고 암호화와 데이터 무결성 인증을 동시에 제공하는 GCM 모드까지 다양한 운용 방식이 있으며, 목적에 맞는 안전한 운용 방식을 선택하는 것이 매우 중요합니다.")

with col2:
    st.header("계산기")
    
    calc_options = st.selectbox(
        "계산기 선택",
        [
            "GF(2^8) 연산",
            "SubBytes Affine 변환",
            "ShiftRows 계산",
            "MixColumns 다항식 곱셈"
        ],
        label_visibility="collapsed"
    )

    if calc_options == "GF(2^8) 연산":
        st.subheader("GF(2^8) 덧셈/곱셈 계산기")
        st.write("두 개의 16진수(00-ff)를 입력하세요.")
        c1, c2 = st.columns(2)
        hex_a = c1.text_input("첫 번째 수 (Hex)", "00")
        hex_b = c2.text_input("두 번째 수 (Hex)", "00")

        if st.button("계산"):
            try:
                val_a = int(hex_a, 16)
                val_b = int(hex_b, 16)
                if not (0 <= val_a <= 255 and 0 <= val_b <= 255):
                    raise ValueError("값은 00과 ff 사이여야 합니다.")

                add_res = utils.gadd(val_a, val_b)
                mul_res = utils.gmul(val_a, val_b)

                st.latex(f"덧셈 (XOR): {hex_a} \\oplus {hex_b} = {add_res:02x}")
                st.latex(f"곱셈: {hex_a} \\times {hex_b} = {mul_res:02x}")

            except ValueError as e:
                st.error(f"입력 오류: {e}. 16진수 두 자리로 입력해주세요 (예: 5a, 0f).")


    elif calc_options == "SubBytes Affine 변환":
        st.subheader("SubBytes 계산기")
        st.write("하나의 16진수(00-ff)를 입력하세요.")
        hex_val = st.text_input("입력 (Hex)", "00")

        if st.button("계산"):
            try:
                val = int(hex_val, 16)
                if not (0 <= val <= 255):
                    raise ValueError("값은 00과 ff 사이여야 합니다.")

                inverse = utils.ginv(val)
                affine_res = utils.affine_transform(inverse)
                sbox_val = utils.sub_byte(val)

                st.markdown(f"**입력:** `{val:02x}`")
                st.markdown(f"**1. 곱셈 역원:** `inv({val:02x}) = {inverse:02x}`")
                st.markdown(f"**2. Affine 변환:** `affine({inverse:02x}) = {affine_res:02x}`")
                st.markdown(f"**최종 S-Box 값:** `S({val:02x}) = {sbox_val:02x}`")
                st.info("SubBytes는 1단계(곱셈 역원)와 2단계(Affine 변환)를 합친 과정입니다.")

            except ValueError as e:
                st.error(f"입력 오류: {e}. 16진수 두 자리로 입력해주세요 (예: 5a, 0f).")


    elif calc_options == "ShiftRows 계산":
        st.subheader("ShiftRows 계산기")
        default_state = "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"
        state_hex = st.text_area("16바이트 State (16진수, 공백으로 구분)", default_state, height=100)

        if st.button("계산"):
            try:
                state_bytes = [int(b, 16) for b in state_hex.split()]
                if len(state_bytes) != 16:
                    raise ValueError("16개의 바이트를 입력해야 합니다.")
                
                state_matrix = utils.state_to_matrix(state_bytes)
                shifted_matrix = utils.shift_rows(state_matrix)

                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**원본 State**")
                    st.code(format_matrix(state_matrix), language='text')
                with c2:
                    st.markdown("**ShiftRows 후**")
                    st.code(format_matrix(shifted_matrix), language='text')

            except ValueError as e:
                st.error(f"입력 오류: {e}. 16개의 16진수 바이트를 공백으로 구분하여 입력하세요.")
        
    elif calc_options == "MixColumns 다항식 곱셈":
        st.subheader("MixColumns 다항식 곱셈 계산기")
        st.write("4바이트 열(c0, c1, c2, c3)과 고정 다항식 a(x) = `03x^3+01x^2+01x+02`의 곱셈을 계산합니다.")
        
        c1, c2, c3, c4 = st.columns(4)
        col_hex = [
            c1.text_input("c0", "00"),
            c2.text_input("c1", "00"),
            c3.text_input("c2", "00"),
            c4.text_input("c3", "00")
        ]

        if st.button("계산"):
            try:
                col_bytes = [int(b, 16) for b in col_hex]
                if any(not (0 <= b <= 255) for b in col_bytes):
                    raise ValueError("각 바이트는 00과 ff 사이여야 합니다.")

                # 요청된 특정 다항식 곱셈
                result_poly = utils.mix_columns_poly_mult(col_bytes)
                # 표준 MixColumns 연산
                result_std = utils.mix_columns(col_bytes)

                st.markdown(f"**입력 열 c(x):** `[{', '.join(f'{b:02x}' for b in col_bytes)}]`")
                st.markdown(f"**a(x) * c(x) mod (x^4+1) 결과:** `[{', '.join(f'{b:02x}' for b in result_poly)}]`")
                st.markdown(f"**표준 MixColumns 연산 결과:** `[{', '.join(f'{b:02x}' for b in result_std)}]`")
                st.info("사용자가 요청한 다항식 곱셈은 표준 MixColumns 행렬 곱셈의 한 열을 계산하는 것과 동일한 원리입니다.")

            except ValueError as e:
                st.error(f"입력 오류: {e}. 각 필드에 16진수 두 자리를 입력하세요.")

