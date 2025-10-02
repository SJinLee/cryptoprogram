# 프로젝트 목표
- AES를 실험하는 web app를 만드는 것
- web page들의 내용은 한글로 만들어줘.

# 도구
- python을 사용
- 알고리즘은 python으로 작성 또는 library이용
- streamlit, unicorn, flask, Django, nodejs, React 를 모두 시도할 수 있나? 아니면 하나를 선택

# 전체화면
- 화면의 가장 윗부분에 128, 196,256중 하나를 선택하는 영역이 탭 버튼 위에 있어서 모든 page에서 볼 수 있도록 하고, 이것을 선택하면 page의 모든 내용이 초기화되어야 함
- 화면의 아랫 부분은 세로로 2개의 영역으로 나눔
- 왼쪽 영역은 tab으로 만들어 어느 페이지에서도 다른 페이지로 이동할 수 있도록 해야함. page의 구성은 아래에 설명됨
- 오른쪽 부분은 GL(2^8)의 덧셈, 곱셈을 계산할 수 있는 화면, subbytes의 affine변환을 계산하는 화면, Shift를 계산하는 화면, 03x^3+01x^2+01x+02와 곱하여 mod x^4+1을 계산하는 화면이 버튼에 따라 바뀌도록 만들면됨

# page 구성
- AES에 대한 설명: AES의 역사와 간략한 소개가 들어있는 화면
- subbytes, shiftrows, mixcolumns의 계산과정을 설명하는 화면
- 라운드 키 만드과정: Key Expansion 의사코드와 주어진 키에서 128bit round key를 계산한 결과도 보여주는 화면
- 각 라운드의 암호화 결과를 보여주는 화면: SubBytes, ShiftRows, MixColumns, round key의 XOR결과도 보여주어야 함
- 쇄도효과를 보여주는 화면
- 암호 해독 방법: brute force attack을 실험하는 과정을 보여주는 화면
- 다른 알려진 암호 해독 방법 소개 화면
- AES에 대한 특이한 사항 또는 연구결과 등과 관련된 설명을 하는 화면

# 기타
