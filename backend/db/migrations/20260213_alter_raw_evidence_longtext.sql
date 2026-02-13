USE kisa_security;

ALTER TABLE scan_history
    MODIFY COLUMN raw_evidence LONGTEXT NOT NULL;

ALTER TABLE remediation_logs
    MODIFY COLUMN raw_evidence LONGTEXT NOT NULL;
