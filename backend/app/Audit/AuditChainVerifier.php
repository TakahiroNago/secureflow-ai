<?php

namespace App\Audit;

use Illuminate\Support\Facades\DB;
use JsonException;
use stdClass;

/**
 * Recomputes one chain in PHP, from one snapshot, without taking the head lock.
 * docs/database-design.md §3.12.5. What it cannot see is documented there: a recomputed chain and a
 * rewound head look valid unless a head saved earlier is supplied as an anchor.
 */
final class AuditChainVerifier
{
    private const BATCH = 500;

    /**
     * @param  array{last_seq: int, last_hash: string}|null  $anchor
     * @return array{valid: bool, chain_id: string, checked_count: int, first_broken_seq: ?int, reason_code: ?string, suppressed_events: int}
     */
    public function verify(string $chainId, ?array $anchor = null): array
    {
        $db = DB::connection(AuditAvailability::READ_CONNECTION);

        return $db->transaction(function () use ($db, $chainId, $anchor) {
            $db->statement('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
            $db->statement("SELECT set_config('statement_timeout', '0', true), set_config('idle_in_transaction_session_timeout', '0', true)");

            $head = $db->selectOne('SELECT last_seq, last_hash FROM audit_chain_heads WHERE chain_id = ?::uuid', [$chainId]);

            $expectedSeq = 1;
            $previous = AuditCanonicalizer::GENESIS;
            $checked = 0;
            $suppressed = 0;
            $anchorHash = null;
            $version = 1;

            do {
                $rows = $db->select(
                    <<<'SQL'
                    SELECT event_id::text, organization_id::text, chain_id::text, chain_seq, hash_version, actor_type,
                           actor_user_id::text, event_type, resource_type, resource_id::text, result, severity,
                           host(ip_address) AS ip, masklen(ip_address) AS mask, family(ip_address) AS family,
                           request_id::text, metadata::text AS metadata,
                           to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred, prev_hash, hash
                    FROM audit_logs WHERE chain_id = ?::uuid AND chain_seq >= ? ORDER BY chain_seq LIMIT ?
                    SQL,
                    [$chainId, $expectedSeq, self::BATCH],
                );

                foreach ($rows as $row) {
                    $broken = $this->check($row, $chainId, $expectedSeq, $previous, $version);
                    if ($broken !== null) {
                        return $this->result($chainId, $checked, $broken[0], $broken[1], $suppressed);
                    }

                    $version = (int) $row->hash_version;
                    $previous = (string) $row->hash;
                    $checked++;
                    $expectedSeq++;

                    if ($row->event_type === AuditEventType::EventsSuppressed->value) {
                        $suppressed++;
                    }
                    if ($anchor !== null && (int) $row->chain_seq === $anchor['last_seq']) {
                        $anchorHash = (string) $row->hash;
                    }
                }
            } while (count($rows) === self::BATCH);

            if ($head === null) {
                return $checked > 0
                    ? $this->result($chainId, $checked, $expectedSeq, 'HEAD_MISSING', $suppressed)
                    : $this->anchorResult($chainId, $checked, $anchor, $anchorHash, $suppressed);
            }

            if ((int) $head->last_seq !== $checked || (string) $head->last_hash !== ($checked === 0 ? AuditCanonicalizer::GENESIS : $previous)) {
                return $this->result($chainId, $checked, $expectedSeq, 'HEAD_MISMATCH', $suppressed);
            }

            return $this->anchorResult($chainId, $checked, $anchor, $anchorHash, $suppressed);
        }, 1);
    }

    /**
     * @return array{0: int, 1: string}|null
     */
    private function check(stdClass $row, string $chainId, int $expectedSeq, string $previous, int $version): ?array
    {
        $seq = (int) $row->chain_seq;

        if ($seq !== $expectedSeq) {
            return [$expectedSeq, 'SEQUENCE_GAP'];
        }
        if ((int) $row->hash_version !== 1 || (int) $row->hash_version < $version) {
            return [$seq, 'UNSUPPORTED_VERSION'];
        }
        if ($row->chain_id !== ($row->organization_id ?? AuditCanonicalizer::SYSTEM_CHAIN) || $row->chain_id !== $chainId) {
            return [$seq, 'CHAIN_ID_MISMATCH'];
        }
        if ($row->ip !== null && (int) $row->mask !== ((int) $row->family === 4 ? 32 : 128)) {
            return [$seq, 'NON_CANONICAL_VALUE'];
        }
        if ((string) $row->prev_hash !== $previous) {
            return [$seq, 'PREV_HASH_MISMATCH'];
        }

        try {
            $metadata = AuditCanonicalizer::metadata((string) $row->metadata);
        } catch (JsonException) {
            return [$seq, 'NON_CANONICAL_VALUE'];
        }

        $hash = AuditCanonicalizer::hash([
            $row->chain_id, (string) $seq, $row->prev_hash, $row->event_id, $row->organization_id, $row->actor_type,
            $row->actor_user_id, $row->event_type, $row->resource_type, $row->resource_id, $row->result, $row->severity,
            $row->ip, $row->request_id, $metadata, $row->occurred,
        ]);

        return hash_equals((string) $row->hash, $hash) ? null : [$seq, 'HASH_MISMATCH'];
    }

    /**
     * @param  array{last_seq: int, last_hash: string}|null  $anchor
     * @return array{valid: bool, chain_id: string, checked_count: int, first_broken_seq: ?int, reason_code: ?string, suppressed_events: int}
     */
    private function anchorResult(string $chainId, int $checked, ?array $anchor, ?string $anchorHash, int $suppressed): array
    {
        if ($anchor !== null && $anchor['last_seq'] > 0 && ($anchorHash === null || ! hash_equals($anchor['last_hash'], $anchorHash))) {
            return $this->result($chainId, $checked, $anchor['last_seq'], 'ANCHOR_MISMATCH', $suppressed);
        }

        return $this->result($chainId, $checked, null, null, $suppressed);
    }

    /**
     * @return array{valid: bool, chain_id: string, checked_count: int, first_broken_seq: ?int, reason_code: ?string, suppressed_events: int}
     */
    private function result(string $chainId, int $checked, ?int $brokenSeq, ?string $reason, int $suppressed): array
    {
        return [
            'valid' => $reason === null,
            'chain_id' => $chainId,
            'checked_count' => $checked,
            'first_broken_seq' => $brokenSeq,
            'reason_code' => $reason,
            'suppressed_events' => $suppressed,
        ];
    }
}
