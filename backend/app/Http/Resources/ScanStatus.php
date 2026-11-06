<?php

namespace App\Http\Resources;

/**
 * Nothing is scanned before step 2-3, and the answer says so rather than leaving it out. The notice is
 * always returned (docs/api-design.md §3.3).
 */
final class ScanStatus
{
    public const LIMITATIONS_NOTICE = '検出は完全ではなく、氏名・住所など自動検出できない個人情報や秘密情報が含まれている可能性があります。検出されなかった情報が存在しないことは保証されません。';

    /**
     * @return array{status: string, decision: string|null, limitations_notice: string}
     */
    public static function of(?string $decision): array
    {
        return [
            'status' => $decision === null ? 'not_scanned' : 'scanned',
            'decision' => $decision,
            'limitations_notice' => self::LIMITATIONS_NOTICE,
        ];
    }
}
