# 프로젝트 목표
- DES를 실험하는 web app를 만드는 것

# 도구
- python을 사용
- 알고리즘은 python으로 작성 또는 library이용
- streamlit, unicorn, flask, Django, nodejs, React 를 모두 시도할 수 있나? 아니면 하나를 선택

# 전체화면
- 아래 page 구성에서 요구하는 page를 만들어야함
- page는 tab으로 만들어 어느 페이지에서도 다른 페이지로 이동할 수 있도록 해야함. 메뉴 형식이어도 좋음

# page 구성
- DES에 대한 설명: DES의 역사와 간략한 소개가 들어있는 화면
- 라운드 키 만드과정: 64bit의 parity 확인하는 과정, PC1치환 후 CD로 나누고 shift후 PC2치환하는 과정을 확인할 수 있도록 만들어야함
- 암호화과정 IP치환부터 L,R로 나누고, E치환, 라운드 키와 xor, SBOX, P치환, L과 xor, Round별 결과를 확인할 수 있도록 만들어야함
- 쇄도효과를 보여주는 화면
- 평문의 작은 변화가 암호문의 큰 변화를 보여주는 실험이 있는 화면
- 암호 해독 방법: brute force attack을 실험하는 과정을 보여주는 화면
- 다른 암호 해독 방법 소개: 있으면

# 기타
- DES에 대한 특이한 사항 또는 연구결과등이 있으면 관련 page를 만들면 좋겠음
