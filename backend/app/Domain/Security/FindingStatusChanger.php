<?php

namespace App\Domain\Security;

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Models\SecurityFinding;
use App\Models\SecurityScan;
use App\Models\User;
use App\Security\Scanning\InputScanner;
use App\Security\Scanning\InputScanResult;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use SensitiveParameter;

/**
 * docs/security-design.md §20. The status of a finding, and the note that explains it. A note is text like any
 * other, so it is scanned and masked before anything is locked, and a secret in it stops the change with a record
 * of the stop and none of the text. The change and its audit record are one transaction: what is not recorded did
 * not happen.
 */
final readonly class FindingStatusChanger
{
    public const NOTE_LIMIT = 500;

    private const FIELD_NOTE = 'status_note';

    public function __construct(
        private InputScanner $scanner,
        private ScanRecorder $recorder,
        private AuditLogger $audit,
        private AuditAvailability $availability,
    ) {}

    /**
     * @param  string|null  $note  Replaces the previous note. Null leaves the new status without one.
     *
     * @throws FindingConflictException when the status cannot change that way
     * @throws InputBlockedException when the scan stopped on the note; its record has committed
     * @throws ValidationException when masking made the note too long
     * @throws ServiceUnavailableException when the audit record cannot be written
     */
    public function change(User $admin, SecurityFinding $finding, FindingStatus $to, #[SensitiveParameter] ?string $note): SecurityFinding
    {
        if (! FindingStatus::from($finding->status)->canChangeTo($to)) {
            throw FindingConflictException::invalidTransition();
        }

        $this->availability->assertAvailable();

        $result = $note === null ? null : $this->scan($admin, $finding, $note);

        return SingleAttemptTransaction::run(DB::connection(), function () use ($admin, $finding, $to, $result): SecurityFinding {
            $locked = SecurityFinding::query()->whereKey($finding->id)->lockForUpdate()->firstOrFail();
            $from = FindingStatus::from($locked->status);

            // Read under the lock: another admin may have decided first.
            if (! $from->canChangeTo($to)) {
                throw FindingConflictException::invalidTransition();
            }

            if ($result !== null) {
                $this->recorder->record($admin, SecurityScan::TARGET_INPUT, $locked->id, $result);
            }

            $locked->forceFill([
                'status' => $to->value,
                'status_note' => $result?->maskedFields[self::FIELD_NOTE] ?? null,
                'status_changed_by' => $admin->id,
                'status_changed_at' => now(),
            ])->save();

            $this->audit->recordInTransaction(
                AuditEntry::byUserOn(AuditEventType::FindingStatusChanged, $admin, 'security_finding', $locked->id, ['from' => $from->value, 'to' => $to->value]),
                'finding_status_unrecorded',
            );

            return $locked;
        });
    }

    /**
     * Before the lock, because a scan can take seconds. A stop is recorded on its own, so that it is kept
     * whatever happens next.
     *
     * @throws InputBlockedException
     * @throws ValidationException
     */
    private function scan(User $admin, SecurityFinding $finding, #[SensitiveParameter] string $note): InputScanResult
    {
        $result = $this->scanner->scanFields([self::FIELD_NOTE => $note]);

        if ($result->blocks()) {
            SingleAttemptTransaction::run(DB::connection(), fn () => $this->recorder->record($admin, SecurityScan::TARGET_INPUT, $finding->id, $result));

            throw new InputBlockedException($result);
        }

        if (mb_strlen(($result->maskedFields ?? [])[self::FIELD_NOTE] ?? '', 'UTF-8') > self::NOTE_LIMIT) {
            throw ValidationException::withMessages([self::FIELD_NOTE => ['マスキング後の文字数が上限を超えます。短くしてください。']]);
        }

        return $result;
    }
}
