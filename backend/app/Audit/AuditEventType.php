<?php

namespace App\Audit;

/**
 * The events recorded so far (docs/security-design.md §16.1). The database checks only their shape,
 * so that adding one does not change the DB function.
 */
enum AuditEventType: string
{
    case Login = 'auth.login';
    case LoginFailed = 'auth.login_failed';
    case Logout = 'auth.logout';
    case Locked = 'auth.locked';
    case PasswordChanged = 'auth.password_changed';
    case PasswordChangeFailed = 'auth.password_change_failed';
    case VerificationFailed = 'audit.verification_failed';
    case EventsSuppressed = 'audit.events_suppressed';
    case AvailabilityChecked = 'audit.availability_checked';
    case WorkflowCreated = 'workflow.created';
    case WorkflowUpdated = 'workflow.updated';
    case WorkflowSubmitted = 'workflow.submitted';
    case WorkflowReopened = 'workflow.reopened';
    case ApprovalApproved = 'approval.approved';
    case ApprovalRejected = 'approval.rejected';
    case ApprovalDenied = 'approval.denied';
    case ExecutionStarted = 'execution.started';
    case ExecutionCompleted = 'execution.completed';
    case ExecutionFailed = 'execution.failed';
    case ExecutionDenied = 'execution.denied';
    case AiCall = 'ai.call';
    case AuthzDenied = 'authz.denied';
    case RateLimitExceeded = 'rate_limit.exceeded';
    case AnalysisFailed = 'analysis.failed';
    case SecurityScan = 'security.scan';
    case SecurityBlocked = 'security.blocked';
    case FindingStatusChanged = 'finding.status_changed';
    case SettingsUpdated = 'settings.updated';
    case SelftestStarted = 'selftest.started';
    case SelftestCompleted = 'selftest.completed';

    /**
     * Anything else in metadata is dropped before recording.
     *
     * @return list<string>
     */
    public function allowedMetadata(): array
    {
        return match ($this) {
            self::LoginFailed, self::PasswordChangeFailed => ['reason_code'],
            self::VerificationFailed => ['chain_id', 'first_broken_seq', 'reason_code'],
            self::EventsSuppressed => ['suppressed_count', 'window_started_at'],
            self::AvailabilityChecked => ['outage_id'],
            self::WorkflowCreated => ['revision_no'],
            self::WorkflowUpdated => ['revision_no', 'change'],
            self::WorkflowSubmitted, self::WorkflowReopened => ['revision_no'],
            self::ApprovalApproved, self::ApprovalRejected => ['revision_no', 'plan_hash'],
            self::ApprovalDenied, self::ExecutionDenied => ['reason_code'],
            self::ExecutionStarted => ['execution_id', 'revision_no'],
            self::ExecutionCompleted => ['execution_id'],
            self::ExecutionFailed => ['execution_id', 'reason_code'],
            self::AiCall => ['provider', 'model', 'total_tokens', 'reason_code'],
            self::AuthzDenied => ['route', 'status'],
            self::RateLimitExceeded => ['route'],
            self::AnalysisFailed => ['reason_code', 'analysis_id'],
            self::SecurityScan => ['target_type', 'decision', 'max_severity', 'findings_count'],
            self::SecurityBlocked => ['reason_code'],
            // The statuses only: the note is text, and text does not go into the chain.
            self::FindingStatusChanged => ['from', 'to'],
            // The new values. They are numbers, and the previous ones are in the previous record.
            self::SettingsUpdated => ['monthly_token_limit', 'user_daily_request_limit', 'max_input_chars'],
            // Counts and codes: the results are in their own table, and hold no text either.
            self::SelftestCompleted => ['total', 'passed', 'failed', 'status', 'reason_code'],
            default => [],
        };
    }

    public function severity(): ?string
    {
        return match ($this) {
            self::LoginFailed, self::PasswordChangeFailed, self::AnalysisFailed, self::ExecutionFailed, self::AuthzDenied, self::RateLimitExceeded => 'low',
            self::Locked, self::SecurityBlocked, self::ApprovalDenied, self::ExecutionDenied => 'medium',
            self::EventsSuppressed => 'high',
            self::VerificationFailed => 'critical',
            default => null,
        };
    }
}
