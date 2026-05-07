# Sentinel-AI Security Policy Rules

## Core Principles
This document defines the security policy rules that the Validation Agent MUST follow when analyzing security events and determining appropriate actions.

## IP Blocking Rules

### ALLOW Conditions
- **ADMIN_IP Protection**: NEVER block or restrict the IP address defined as ADMIN_IP in environment variables
- **Whitelist**: IPs in the whitelist file are always allowed
- **Successful Authentication**: After successful login, reset failure counter for that IP

### DENY Conditions
- **Failed Login Threshold**: DENY and BLOCK IP if failed authentication attempts exceed MAX_FAILED_ATTEMPTS (default: 5) within 10 minutes
- **Brute Force Pattern**: DENY if detecting rapid sequential login attempts (>10 attempts in 60 seconds)
- **Known Malicious IPs**: BLOCK immediately if IP matches known threat intelligence feeds
- **Port Scanning**: DENY if detecting systematic port scanning behavior
- **Invalid User Attempts**: BLOCK if attempting to access non-existent user accounts repeatedly (>3 attempts)

## SSH Security Rules

### ALLOW Conditions
- **Key-Based Authentication**: ALLOW and LOG all successful SSH key authentications
- **Multi-Factor Success**: ALLOW after successful MFA verification
- **Authorized Keys**: ALLOW connections using pre-authorized SSH keys

### DENY Conditions
- **Password Brute Force**: DENY after 3 failed password attempts in 5 minutes
- **Root Login Attempts**: DENY and ALERT if detecting direct root login attempts via password
- **Deprecated Protocols**: DENY connections using SSH protocol version 1
- **Weak Ciphers**: DENY connections attempting to use weak encryption algorithms

## Firewall Management Rules

### ALLOW Actions
- **Temporary Block**: ALLOW temporary IP blocks (auto-expire after 24 hours)
- **Rate Limiting**: ALLOW rate limit rules for suspicious but not clearly malicious IPs
- **Logging Rules**: ALLOW creation of logging rules for audit purposes

### DENY Actions
- **Admin IP Block**: DENY any attempt to block ADMIN_IP
- **Self-Block**: DENY blocking the server's own IP addresses
- **Critical Service Block**: DENY blocking ports 22 (SSH) for ADMIN_IP
- **Permanent Blocks**: DENY permanent blocks without human approval (require HITL=True)

## Log Analysis Rules

### Alert Triggers
- **Critical**: Immediate alert for root compromise attempts, privilege escalation, or data exfiltration
- **High**: Alert for repeated authentication failures, suspicious sudo usage, unauthorized service changes
- **Medium**: Log for unusual access patterns, off-hours access, geographic anomalies
- **Low**: Record for compliance purposes

## Validation Agent Decision Framework

When processing a security event, the Validation Agent MUST:

1. **Query RAG Context**: Search this policy document for relevant ALLOW/DENY rules
2. **Match Conditions**: Identify which rules apply to the current situation
3. **Apply Precedence**: DENY rules take precedence over ALLOW rules in case of conflict
4. **Admin Protection**: Always check if action affects ADMIN_IP before proceeding
5. **Default Deny**: If policy is unclear or RAG unavailable, default to DENY and request HITL review

## Audit Requirements

All actions taken by Sentinel-AI MUST be logged with:
- Timestamp (UTC)
- Event type
- Source IP
- Action taken (ALLOW/DENY/BLOCK)
- Validation Agent reasoning
- Policy rule matched
- Human approval status (if HITL=True)

## Emergency Procedures

### System Lockdown
In case of active breach detection:
1. ALLOW immediate blocking of attack source IPs
2. ALLOW rate limiting of all incoming connections
3. REQUIRE HITL for service shutdown or critical changes
4. ALERT administrators via all available channels

### False Positive Handling
If legitimate traffic is blocked:
1. Admin can override via HITL interface
2. Update whitelist to prevent recurrence
3. Log incident for policy refinement
4. Temporary bypass available for ADMIN_IP

## Policy Updates

This policy can be updated via:
- Human administrator review and approval
- Automated learning from HITL decisions
- Integration with external threat intelligence
- Regular security audits and assessments

---
**Last Updated**: 2025-01-01
**Version**: 1.0.0
**Review Cycle**: Monthly