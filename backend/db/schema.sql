CREATE DATABASE IF NOT EXISTS kisa_security
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_general_ci;

USE kisa_security;

CREATE TABLE IF NOT EXISTS servers (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    server_id       VARCHAR(100)    NOT NULL UNIQUE,
    company         VARCHAR(100)    NOT NULL,
    hostname        VARCHAR(100)    NOT NULL,
    ip_address      VARCHAR(45)     NOT NULL,
    ssh_port        VARCHAR(10)     NOT NULL DEFAULT '22',
    os_type         VARCHAR(100)    NOT NULL,
    db_type         VARCHAR(100)    DEFAULT NULL,
    db_port         VARCHAR(10)     DEFAULT NULL,
    db_user         VARCHAR(100)    DEFAULT NULL,
    db_passwd       LONGTEXT    NOT NULL,
    is_active       BOOLEAN         NOT NULL DEFAULT 1,
    manager         VARCHAR(100)    NOT NULL,
    department      VARCHAR(100)    NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS kisa_items (
    item_code               VARCHAR(10)     PRIMARY KEY,
    category                VARCHAR(50)     NOT NULL,
    title                   VARCHAR(200)    NOT NULL,
    severity                VARCHAR(10)     NOT NULL,
    description             VARCHAR(500)    NOT NULL,
    auto_fix                BOOLEAN         NOT NULL DEFAULT 1,
    auto_fix_description    VARCHAR(500)    DEFAULT NULL,
    guide                   VARCHAR(1000)   NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scan_history (
    scan_id         INT AUTO_INCREMENT PRIMARY KEY,
    server_id       VARCHAR(100)    NOT NULL,
    item_code       VARCHAR(10)     NOT NULL,
    status          VARCHAR(10)     NOT NULL,
    raw_evidence    LONGTEXT        NOT NULL,
    scan_date       DATETIME        NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(server_id),
    FOREIGN KEY (item_code) REFERENCES kisa_items(item_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS remediation_logs (
    log_id          INT AUTO_INCREMENT PRIMARY KEY,
    server_id       VARCHAR(100)    NOT NULL,
    item_code       VARCHAR(10)     NOT NULL,
    action_date     DATETIME        NOT NULL,
    is_success      BOOLEAN         NOT NULL,
    failure_reason  VARCHAR(500)    DEFAULT NULL,
    raw_evidence    LONGTEXT        NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(server_id),
    FOREIGN KEY (item_code) REFERENCES kisa_items(item_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS exceptions (
    exception_id    INT AUTO_INCREMENT PRIMARY KEY,
    server_id       VARCHAR(100)    NOT NULL,
    item_code       VARCHAR(10)     NOT NULL,
    reason          VARCHAR(500)    NOT NULL,
    valid_date      DATETIME        NOT NULL,
    FOREIGN KEY (server_id) REFERENCES servers(server_id),
    FOREIGN KEY (item_code) REFERENCES kisa_items(item_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS users (
    user_id         INT AUTO_INCREMENT PRIMARY KEY,
    user_name       VARCHAR(100)    NOT NULL UNIQUE,
    user_passwd     VARCHAR(255)    NOT NULL,
    role            VARCHAR(20)     NOT NULL DEFAULT 'VIEWER',
    company         VARCHAR(100)    NOT NULL,
    last_login      DATETIME        NOT NULL,
    created_at      DATETIME        NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
