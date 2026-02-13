USE kisa_security;

ALTER TABLE remediation_logs
    ADD COLUMN failure_reason VARCHAR(500) DEFAULT NULL AFTER is_success;
