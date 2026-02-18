"""
초기 사용자 계정 시딩 스크립트
- admin / admin1234
- viewer / viewer1234
"""

from datetime import datetime
from sqlalchemy.orm import Session
from db.session import SessionLocal, engine
from db.models import User, Base
from core.security import hash_password


def seed_users():
    """초기 사용자 계정 생성"""

    # 테이블 생성 (없으면)
    Base.metadata.create_all(bind=engine)

    db: Session = SessionLocal()

    try:
        # 기존 admin, viewer 계정 삭제 (초기화)
        db.query(User).filter(User.user_name.in_(["admin", "viewer"])).delete()
        db.commit()

        # admin 계정 생성
        admin = User(
            user_name="admin",
            user_passwd=hash_password("admin1234"),
            prev_user_passwd=None,
            role="ADMIN",
            company="INTERNAL",
            must_change_password=True,  # 최초 로그인 시 비밀번호 변경 강제
            password_changed_at=None,
            last_login=datetime.now(),
            created_at=datetime.now()
        )
        db.add(admin)

        # viewer 계정 생성
        viewer = User(
            user_name="viewer",
            user_passwd=hash_password("viewer1234"),
            prev_user_passwd=None,
            role="VIEWER",
            company="INTERNAL",
            must_change_password=True,  # 최초 로그인 시 비밀번호 변경 강제
            password_changed_at=None,
            last_login=datetime.now(),
            created_at=datetime.now()
        )
        db.add(viewer)

        db.commit()

        print("✅ 초기 계정 생성 완료!")
        print(f"   - admin / admin1234 (role: ADMIN, must_change_password: True)")
        print(f"   - viewer / viewer1234 (role: VIEWER, must_change_password: True)")

    except Exception as e:
        db.rollback()
        print(f"❌ 에러 발생: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_users()
