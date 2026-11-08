<?php

namespace App\SelfTest\Cases;

use App\Audit\AuditChainVerifier;
use App\SelfTest\CaseOutcome;
use App\SelfTest\ClosureCase;
use App\SelfTest\SelfTestContext;
use Illuminate\Support\Facades\DB;

/**
 * The audit log as it is: the organization's chain verified on committed rows, and the table's refusal of any change.
 * Not isolated: the verification has to read what is committed, and the refused statements roll back on their own.
 */
final class AuditCases
{
    private const CATEGORY = 'audit';

    /**
     * @return list<ClosureCase>
     */
    public static function cases(): array
    {
        return [
            new ClosureCase('ST-28', self::CATEGORY, '監査ログの改変拒否とチェーンの検証', '変更・削除が拒否され、組織のチェーンに矛盾がない', function (SelfTestContext $context): CaseOutcome {
                $update = $context->attempt(fn () => DB::table('audit_logs')->where('organization_id', $context->organizationId)->limit(1)->update(['result' => 'success']));
                $delete = $context->attempt(fn () => DB::table('audit_logs')->where('organization_id', $context->organizationId)->limit(1)->delete());
                $verification = app(AuditChainVerifier::class)->verify($context->organizationId);

                return CaseOutcome::all([
                    'update_refused' => $update !== null,
                    'delete_refused' => $delete !== null,
                    // How many rows there were is in the details: an empty chain is valid, and in use the run's own start is on it.
                    'chain_valid' => $verification['valid'] === true,
                ], '変更を拒否、チェーンは有効', ['checked_count' => $verification['checked_count'], 'sqlstate_update' => $update, 'sqlstate_delete' => $delete]);
            }, isolated: false),
        ];
    }
}
