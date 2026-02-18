```mermaid
graph TB
    subgraph USER["👤 사용자"]
        Browser["브라우저"]
    end

    subgraph FRONTEND["Frontend (React SPA)"]
        direction TB
        React["React 18.2 + TypeScript 5.3<br/>Vite 5.0 빌드"]
        FE_Libs["Zustand · React Query · Axios<br/>React Router · Recharts<br/>React Hook Form · Zod"]
    end

    subgraph BACKEND["Backend (FastAPI)"]
        direction TB
        FastAPI["FastAPI 0.115 + Uvicorn<br/>:8000"]
        
        subgraph API_ROUTES["API 라우터"]
            Auth["auth<br/>JWT 로그인·비밀번호"]
            Assets["assets<br/>서버 자산 CRUD"]
            Scan["scan<br/>점검 실행·결과"]
            Fix["fix<br/>자동조치 실행·진행률"]
            Analysis["analysis<br/>분석 데이터"]
            Dashboard["dashboard<br/>통계·점수"]
            Exceptions["exceptions<br/>예외 처리"]
        end

        subgraph CORE["Core"]
            Security["PBKDF2-SHA256<br/>260K iterations"]
            JWT["JWT HS256<br/>python-jose"]
            Fernet["Fernet AES<br/>DB 비밀번호 암호화"]
            RBAC["RBAC<br/>ADMIN · VIEWER"]
        end

        subgraph SERVICES["Services"]
            FixSvc["fix_service.py<br/>서버 타겟팅 + 항목 필터링"]
            ScanSvc["scan_service.py"]
            AssetSvc["asset_service.py"]
            SyncInv["sync_inventory.py<br/>DB → Ansible 인벤토리"]
        end

        ORM["SQLAlchemy 2.0<br/>mysql-connector 9.1"]
    end

    subgraph JOBAPI["Job API (내부)"]
        direction TB
        JobFastAPI["FastAPI :8001<br/>내부 전용"]
        SQLiteQ["SQLite<br/>작업 큐"]
        Worker["Worker Thread<br/>subprocess 실행"]
    end

    subgraph ORCHESTRATOR["오케스트레이터"]
        RunSh["run.sh<br/>scan · fix · scan-db · fix-db"]
        Pipeline["run_pipeline.py<br/>JSON 파싱 → DB INSERT"]
    end

    subgraph ANSIBLE["Ansible"]
        direction TB
        AnsibleEngine["Ansible Engine<br/>SSH 키 인증 · sudo"]
        Vault["Ansible Vault<br/>db_passwd 암호화"]
        
        subgraph PLAYBOOKS["Playbooks"]
            ScanOS["scan_os.yml"]
            ScanDB["scan_db.yml"]
            FixOS["fix_os.yml<br/>item_codes 필터"]
            FixDB["fix_db.yml"]
        end

        Inventory["hosts.ini<br/>자동 생성"]
    end

    subgraph SCRIPTS["점검·조치 스크립트 (Bash)"]
        direction LR
        subgraph OS_SCRIPTS["OS (40개 항목)"]
            Account["계정 관리<br/>U-01 ~ U-13"]
            Directory["파일·디렉토리<br/>U-14 ~ U-35"]
            Service["서비스 관리<br/>U-36 ~ U-63"]
            Patch["패치 관리<br/>U-64 ~ U-66"]
            Log["로그 관리<br/>U-67 ~ U-72"]
        end
        subgraph DB_SCRIPTS["DB (8개 항목)"]
            MySQL_S["MySQL<br/>D-01 ~ D-28"]
            PG_S["PostgreSQL<br/>D-01 ~ D-28"]
        end
    end

    subgraph TARGETS["대상 서버"]
        R9_001["autoever-r9-001<br/>192.168.182.128<br/>Rocky 9 · MySQL 8"]
        R9_002["autoever-r9-002<br/>192.168.182.132<br/>Rocky 9 · MySQL 8"]
        R10_001["autoever-r10-001<br/>192.168.182.137<br/>Rocky 10 · PostgreSQL"]
    end

    subgraph DATABASE["Database"]
        MySQL_DB[("MySQL 8.x<br/>kisa_security")]
        
        subgraph TABLES["주요 테이블"]
            T_Servers["servers<br/>자산 목록"]
            T_Items["kisa_items<br/>48개 점검 항목"]
            T_Scan["scan_history<br/>점검 결과"]
            T_Remed["remediation_logs<br/>조치 이력"]
            T_Except["exceptions<br/>예외 처리"]
            T_Users["users<br/>사용자 계정"]
        end
    end

    subgraph TMP["임시 파일 (/tmp/audit/)"]
        TargetJSON["fix_target_server.json<br/>대상 서버 ID"]
        CodesJSON["fix_item_codes.json<br/>조치 항목 코드"]
        CheckDir["check/*.json<br/>점검 결과"]
        FixDir["fix/*.json<br/>조치 결과"]
    end

    %% 연결
    Browser -->|":5173"| React
    React --> FE_Libs
    FE_Libs -->|"REST API :8000<br/>Bearer JWT"| FastAPI

    FastAPI --> API_ROUTES
    FastAPI --> CORE
    FastAPI --> SERVICES
    SERVICES --> ORM
    ORM --> MySQL_DB
    MySQL_DB --- TABLES

    FixSvc -->|"server_id + item_codes<br/>파일 저장"| TMP
    FixSvc -->|"POST /jobs/fix<br/>:8001"| JobFastAPI

    JobFastAPI --> SQLiteQ
    SQLiteQ --> Worker
    Worker -->|"bash -lc ./run.sh fix"| RunSh

    RunSh -->|"sync_inventory<br/>ANSIBLE_LIMIT 설정"| AnsibleEngine
    SyncInv -->|"DB → hosts.ini"| Inventory
    AnsibleEngine --> Vault
    AnsibleEngine --> PLAYBOOKS
    AnsibleEngine --> Inventory

    PLAYBOOKS -->|"SSH + sudo<br/>스크립트 배포·실행"| SCRIPTS
    SCRIPTS -->|"원격 실행"| TARGETS

    TARGETS -->|"JSON 결과<br/>fetch"| TMP
    TMP -->|"파싱"| Pipeline
    Pipeline -->|"INSERT"| MySQL_DB

    R9_001 -.->|"MySQL"| MySQL_S
    R9_002 -.->|"MySQL"| MySQL_S
    R10_001 -.->|"PostgreSQL"| PG_S

    %% 스타일
    classDef frontend fill:#61dafb,stroke:#333,color:#000
    classDef backend fill:#009688,stroke:#333,color:#fff
    classDef db fill:#f57c00,stroke:#333,color:#fff
    classDef ansible fill:#e53935,stroke:#333,color:#fff
    classDef server fill:#5c6bc0,stroke:#333,color:#fff
    classDef tmp fill:#78909c,stroke:#333,color:#fff

    class React,FE_Libs frontend
    class FastAPI,Auth,Assets,Scan,Fix,Analysis,Dashboard,Exceptions,Security,JWT,Fernet,RBAC,FixSvc,ScanSvc,AssetSvc,SyncInv,ORM backend
    class MySQL_DB,T_Servers,T_Items,T_Scan,T_Remed,T_Except,T_Users db
    class AnsibleEngine,Vault,ScanOS,ScanDB,FixOS,FixDB,Inventory ansible
    class R9_001,R9_002,R10_001 server
    class TargetJSON,CodesJSON,CheckDir,FixDir tmp
