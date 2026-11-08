<?php

namespace App\SelfTest\Cases;

use App\Domain\Workflow\WorkflowStatus;
use App\Models\AuditLog;
use App\Models\OrganizationSetting;
use App\Models\SecurityFinding;
use App\Models\User;
use App\Models\Workflow;
use App\SelfTest\CaseOutcome;
use App\SelfTest\ClosureCase;
use App\SelfTest\SelfTestContext;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;

/**
 * The policies, asked directly with models that are never saved (docs/security-design.md §13). Nothing here touches
 * the database.
 */
final class AuthorizationCases
{
    private const CATEGORY = 'authorization';

    /**
     * @return list<ClosureCase>
     */
    public static function cases(): array
    {
        return [
            new ClosureCase('ST-06', self::CATEGORY, 'ロールのない操作（承認・監査ログ・設定・対策状況）', 'Policy が拒否する', function (SelfTestContext $context): CaseOutcome {
                $org = $context->organizationId;
                $member = self::user('member', $org);
                $auditor = self::user('auditor', $org);
                $admin = self::user('admin', $org);
                $pending = self::workflow($org, $member->id, WorkflowStatus::Pending);
                $finding = new SecurityFinding;
                $finding->forceFill(['organization_id' => $org, 'status' => 'open']);

                return CaseOutcome::all([
                    'member_cannot_approve' => Gate::forUser($member)->inspect('approve', $pending)->code() === 'APPROVER_ROLE_REQUIRED',
                    'auditor_cannot_approve' => Gate::forUser($auditor)->inspect('approve', $pending)->code() === 'APPROVER_ROLE_REQUIRED',
                    'auditor_cannot_reject' => Gate::forUser($auditor)->inspect('reject', $pending)->denied(),
                    'member_cannot_read_audit_log' => Gate::forUser($member)->inspect('viewAny', AuditLog::class)->denied(),
                    'member_cannot_change_settings' => Gate::forUser($member)->inspect('update', OrganizationSetting::class)->denied(),
                    'auditor_cannot_change_settings' => Gate::forUser($auditor)->inspect('update', OrganizationSetting::class)->denied(),
                    'auditor_cannot_change_finding' => Gate::forUser($auditor)->inspect('update', $finding)->denied(),
                    'auditor_cannot_create_workflow' => Gate::forUser($auditor)->inspect('create', Workflow::class)->denied(),
                    'admin_can_approve_another_persons' => Gate::forUser($admin)->inspect('approve', $pending)->allowed(),
                ], '8 件を拒否、admin の承認のみ許可', ['checks' => 9]);
            }),

            new ClosureCase('ST-12', self::CATEGORY, '他ユーザー・他組織のデータの参照', '存在を隠して 404 相当で拒否する', function (SelfTestContext $context): CaseOutcome {
                $org = $context->organizationId;
                $otherOrg = (string) Str::uuid7();
                $member = self::user('member', $org);
                $otherMember = self::user('member', $org);
                $admin = self::user('admin', $org);
                $own = self::workflow($org, $member->id, WorkflowStatus::Draft);
                $someoneElses = self::workflow($org, $otherMember->id, WorkflowStatus::Draft);
                $foreign = self::workflow($otherOrg, $member->id, WorkflowStatus::Draft);

                return CaseOutcome::all([
                    'other_organization_hidden' => Gate::forUser($member)->inspect('view', $foreign)->status() === 404,
                    'other_organization_hidden_from_admin' => Gate::forUser($admin)->inspect('view', $foreign)->status() === 404,
                    'other_members_hidden' => Gate::forUser($member)->inspect('view', $someoneElses)->status() === 404,
                    'other_members_not_editable' => Gate::forUser($member)->inspect('update', $someoneElses)->status() === 404,
                    'own_visible' => Gate::forUser($member)->inspect('view', $own)->allowed(),
                    'admin_sees_organization' => Gate::forUser($admin)->inspect('view', $someoneElses)->allowed(),
                ], '別組織と他人のものは 404、自分のものは参照可', ['checks' => 6]);
            }),
        ];
    }

    private static function user(string $role, string $organizationId): User
    {
        $user = new User;
        $user->forceFill(['id' => (string) Str::uuid7(), 'organization_id' => $organizationId, 'role' => $role, 'is_active' => true, 'name' => 'self-test', 'email' => 'self-test@invalid.example']);

        return $user;
    }

    private static function workflow(string $organizationId, string $createdBy, WorkflowStatus $status): Workflow
    {
        $workflow = new Workflow;
        $workflow->forceFill(['id' => (string) Str::uuid7(), 'organization_id' => $organizationId, 'created_by' => $createdBy, 'status' => $status, 'title' => 'self-test']);

        return $workflow;
    }
}
