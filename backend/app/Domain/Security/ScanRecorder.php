<?php

namespace App\Domain\Security;

use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Models\SecurityFinding;
use App\Models\SecurityScan;
use App\Models\User;
use App\Security\Scanning\InputFinding;
use App\Security\Scanning\InputScanResult;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Support\Facades\Log;

/**
 * The scan, its findings and the audit record, in the caller's transaction. Nothing goes on if this cannot be
 * written: a stop with no record of it must not happen.
 */
final readonly class ScanRecorder
{
    public function __construct(private AuditLogger $audit) {}

    /**
     * @param  bool  $keepExcerpts  False when the text itself is not being kept: an excerpt would keep part of it.
     *
     * @throws ServiceUnavailableException when the audit record cannot be written
     */
    public function record(User $user, string $targetType, ?string $targetId, InputScanResult $result, bool $keepExcerpts = true): SecurityScan
    {
        $scan = new SecurityScan;
        $scan->forceFill([
            'user_id' => $user->id,
            'target_type' => $targetType,
            'target_id' => $targetId,
            'ruleset_version' => $result->rulesetVersion,
            'max_severity' => $result->maxSeverity?->value,
            'decision' => $result->decision->value,
            'block_reason' => $result->blockReason,
            'masking_status' => $result->maskingStatus,
            'findings_count' => $result->findingsCount,
            'duration_ms' => $result->durationMs,
        ])->save();

        foreach ($result->findings as $finding) {
            $this->recordFinding($scan, $finding, $keepExcerpts);
        }

        $this->audit->recordInTransaction(
            AuditEntry::byUserOn(AuditEventType::SecurityScan, $user, 'security_scan', $scan->id, array_filter([
                'target_type' => $targetType,
                'decision' => $result->decision->value,
                'max_severity' => $result->maxSeverity?->value,
                'findings_count' => $result->findingsCount,
            ], fn (mixed $value) => $value !== null)),
            'security_scan_unrecorded',
        );

        if ($result->blocks()) {
            $this->audit->recordInTransaction(
                AuditEntry::byUserOn(AuditEventType::SecurityBlocked, $user, 'security_scan', $scan->id, ['reason_code' => (string) $result->blockReason], 'denied'),
                'security_blocked_unrecorded',
            );
        }

        if ($result->failureReason !== null) {
            // Why the scan gave up. The reason is one of a fixed list, and holds no text.
            Log::warning('security.scan_failed', [
                'metric' => 'security.scan_failed',
                'scan_id' => $scan->id,
                'reason' => $result->failureReason,
            ]);
        }

        return $scan;
    }

    private function recordFinding(SecurityScan $scan, InputFinding $finding, bool $keepExcerpts): void
    {
        (new SecurityFinding)->forceFill([
            'scan_id' => $scan->id,
            'category' => $finding->category,
            'rule_id' => $finding->ruleId,
            'severity' => $finding->severity->value,
            'action' => $finding->action->value,
            'message' => $finding->message,
            'masked_excerpt' => $keepExcerpts ? $finding->excerpt : null,
            'field_path' => $finding->field,
            'position_start' => $finding->start,
            'position_end' => $finding->end,
        ])->save();
    }
}
