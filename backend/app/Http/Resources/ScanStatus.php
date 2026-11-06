<?php

namespace App\Http\Resources;

use App\Models\SecurityFinding;
use App\Models\SecurityScan;
use App\Security\Scanning\InputFinding;
use App\Security\Scanning\InputScanResult;

/**
 * docs/api-design.md §3.3. Severity and action are separate fields, and the notice is always returned, because
 * finding nothing never means there is nothing. What was never scanned says so rather than leaving it out.
 */
final class ScanStatus
{
    public const LIMITATIONS_NOTICE = '検出は完全ではなく、氏名・住所など自動検出できない個人情報や秘密情報が含まれている可能性があります。検出されなかった情報が存在しないことは保証されません。';

    /**
     * @return array<string, mixed>
     */
    public static function of(?SecurityScan $scan, ?string $maskedInput = null): array
    {
        if ($scan === null) {
            return [
                'status' => 'not_scanned',
                'decision' => null,
                'block_reason' => null,
                'max_severity' => null,
                'masking_status' => null,
                'findings' => [],
                'findings_count' => 0,
                'limitations_notice' => self::LIMITATIONS_NOTICE,
            ];
        }

        return [
            'status' => 'scanned',
            'decision' => $scan->decision,
            'block_reason' => $scan->block_reason,
            'max_severity' => $scan->max_severity,
            'masking_status' => $scan->masking_status,
            ...($maskedInput === null ? [] : ['masked_input' => $maskedInput]),
            'findings' => $scan->findings
                ->map(fn (SecurityFinding $finding) => [
                    'category' => $finding->category,
                    'rule_id' => $finding->rule_id,
                    'severity' => $finding->severity,
                    'action' => $finding->action,
                    'message' => $finding->message,
                    'field' => $finding->field_path,
                    'position_start' => $finding->position_start,
                    'position_end' => $finding->position_end,
                ])
                ->values()
                ->all(),
            'findings_count' => $scan->findings_count,
            'limitations_notice' => self::LIMITATIONS_NOTICE,
        ];
    }

    /**
     * A scan that has only just run. After a stop there is no masked text to show.
     *
     * @return array<string, mixed>
     */
    public static function ofResult(InputScanResult $result, ?string $maskedInput = null): array
    {
        return [
            'status' => 'scanned',
            'decision' => $result->decision->value,
            'block_reason' => $result->blockReason,
            'max_severity' => $result->maxSeverity?->value,
            'masking_status' => $result->maskingStatus,
            ...($maskedInput === null ? [] : ['masked_input' => $maskedInput]),
            'findings' => array_map(fn (InputFinding $finding) => $finding->toArray(), $result->findings),
            'findings_count' => $result->findingsCount,
            'limitations_notice' => self::LIMITATIONS_NOTICE,
        ];
    }
}
