<?php

namespace App\Audit;

/**
 * The events recorded so far (docs/security-design.md §16.1). The database checks only their shape,
 * so that adding one does not change the DB function. Other events arrive in step 2-7.
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
    case AnalysisFailed = 'analysis.failed';

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
            self::AnalysisFailed => ['reason_code', 'analysis_id'],
            default => [],
        };
    }

    public function severity(): ?string
    {
        return match ($this) {
            self::LoginFailed, self::PasswordChangeFailed, self::AnalysisFailed => 'low',
            self::Locked => 'medium',
            self::EventsSuppressed => 'high',
            self::VerificationFailed => 'critical',
            default => null,
        };
    }
}
