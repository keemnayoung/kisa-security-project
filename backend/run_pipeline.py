"""
backend/run_pipeline.py
전체 파이프라인 메인 엔트리

[사용법]
    python3 run_pipeline.py scan          # 1. (진짜+가짜) 점검 결과 파싱 -> DB 저장
    python3 run_pipeline.py fix           # 2. 조치 결과 파싱 -> DB 저장
    python3 run_pipeline.py score [ID]    # 3. 보안 점수 계산 (ID 생략시 전체)
    python3 run_pipeline.py mock          # 0. 가짜 데이터 생성 (테스트용)
    python3 run_pipeline.py all           # [추천] mock -> scan -> score 한방에 실행
"""

import sys
import os
import importlib.util

# ---------------------------------------------------------
# 1. 경로 설정 (Import Error 방지)
# ---------------------------------------------------------
# 현재 파일(run_pipeline.py)의 위치: PROJECT_ROOT/backend/
current_dir = os.path.dirname(os.path.abspath(__file__))
# 프로젝트 루트: PROJECT_ROOT/
project_root = os.path.dirname(current_dir)

# sys.path에 추가하여 모듈을 찾을 수 있게 함
sys.path.append(current_dir)
sys.path.append(project_root)

# ---------------------------------------------------------
# 2. 모듈 Import
# ---------------------------------------------------------
try:
    from processors.parse_scan_result import parse_and_insert as parse_scan
    from processors.parse_fix_result import parse_and_insert as parse_fix
    from processors.score_calculator import calculate_score
    from db.connector import DBConnector
    print("[INFO] 모듈 로드 성공")
except ImportError as e:
    print(f"[ERROR] 모듈을 찾을 수 없습니다: {e}")
    print("      폴더 구조가 올바른지 확인해주세요 (backend/processors, backend/db)")
    sys.exit(1)


# ---------------------------------------------------------
# 3. 기능 정의
# ---------------------------------------------------------

def run_mock_generator():
    """
    simulation/mock_generator.py를 실행하여 가짜 데이터를 생성합니다.
    """
    print("=" * 50)
    print(" 🛠️  [Step 0] 시뮬레이션 데이터 생성 (97대)")
    print("=" * 50)
    
    mock_script_path = os.path.join(project_root, "simulation", "mock_generator.py")
    
    if os.path.exists(mock_script_path):
        # 파이썬 스크립트 직접 실행
        os.system(f"python3 {mock_script_path}")
    else:
        print(f"[WARNING] 시뮬레이션 스크립트가 없습니다: {mock_script_path}")
        print("          진짜 서버 데이터만 처리합니다.")


def run_scan_pipeline():
    """
    점검 결과(JSON)를 파싱하여 DB에 저장합니다.
    (진짜 서버 결과 + 시뮬레이션 결과 모두 처리)
    """
    print("\n" + "=" * 50)
    print(" 🔍 [Step 1] 점검 결과 파싱 및 DB 저장")
    print("=" * 50)
    
    # 1. JSON 파일들이 있는 디렉토리 설정 (parse_scan_result.py 내부에서 처리하겠지만, 여기서 넘겨줄 수도 있음)
    # 현재는 parse_scan() 내부 로직에 맡김
    return parse_scan()


def run_fix_pipeline():
    print("\n" + "=" * 50)
    print(" 🔧 [Step 2] 조치 결과 파싱 및 DB 저장")
    print("=" * 50)
    return parse_fix()


def run_score_pipeline(server_id=None):
    print("\n" + "=" * 50)
    print(" 💯 [Step 3] 보안 점수 계산")
    print("=" * 50)

    if server_id:
        print(f" -> 대상 서버: {server_id}")
        return calculate_score(server_id)
    else:
        # 전체 서버 계산
        db = DBConnector()
        if not db.connect():
            return None

        servers = db.get_active_servers()
        db.disconnect()

        if not servers:
            print("[INFO] 활성화된 서버가 없습니다.")
            return None

        print(f" -> 전체 {len(servers)}개 서버 점수 재계산 중...")
        results = []
        for server in servers:
            # 진행상황 표시 (선택)
            # print(f"Processing {server['server_id']}...", end='\r')
            calculate_score(server['server_id'])
            
        print(f"\n[SUCCESS] 전체 서버 점수 계산 완료")
        return results


def run_all():
    """
    전체 파이프라인 순차 실행
    Mock 생성 -> Scan 파싱 -> Score 계산
    """
    print("\n🚀 [START] 전체 시스템 파이프라인 가동\n")
    
    # 1. 가짜 데이터 생성
    run_mock_generator()
    
    # 2. 점검 결과 파싱 (진짜+가짜)
    run_scan_pipeline()
    
    # 3. 점수 계산
    run_score_pipeline()
    
    print("\n✅ [FINISH] 모든 작업이 완료되었습니다. 대시보드를 확인하세요.\n")


# ---------------------------------------------------------
# 4. 메인 실행
# ---------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("\n[사용법]")
        print(" python3 run_pipeline.py mock    # 가짜 데이터 생성")
        print(" python3 run_pipeline.py scan    # 점검 결과 파싱")
        print(" python3 run_pipeline.py fix     # 조치 결과 파싱")
        print(" python3 run_pipeline.py score   # 점수 계산")
        print(" python3 run_pipeline.py all     # 전체 실행 (추천)")
        sys.exit(1)

    command = sys.argv[1]

    if command == 'mock':
        run_mock_generator()
    elif command == 'scan':
        run_scan_pipeline()
    elif command == 'fix':
        run_fix_pipeline()
    elif command == 'score':
        server_id = sys.argv[2] if len(sys.argv) > 2 else None
        run_score_pipeline(server_id)
    elif command == 'all':
        run_all()
    else:
        print(f"[ERROR] 알 수 없는 명령어: {command}")
        sys.exit(1)

if __name__ == '__main__':
    main()