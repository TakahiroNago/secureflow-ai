<?php

namespace App\SelfTest\Cases;

use App\Ai\Providers\MockScenario;
use App\Domain\Execution\ExecutionVerifier;
use App\Domain\Workflow\AiUsageLedger;
use App\Domain\Workflow\ApprovalEligibility;
use App\Domain\Workflow\PlanHasher;
use App\Domain\Workflow\WorkflowConflictException;
use App\Domain\Workflow\WorkflowEvent;
use App\Domain\Workflow\WorkflowStateMachine;
use App\Domain\Workflow\WorkflowStatus;
use App\Models\AiUsageLog;
use App\Models\Approval;
use App\Models\OrganizationSetting;
use App\Models\User;
use App\Models\Workflow;
use App\Models\WorkflowExecution;
use App\SelfTest\CaseOutcome;
use App\SelfTest\ClosureCase;
use App\SelfTest\SelfTestContext;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;

/**
 * The workflow from draft to execution, driven through the services where they succeed, and checked with the
 * decision components and the database's own rules where they refuse (docs/security-design.md §9, §10, §11).
 * Every row these cases make is inside the case's transaction, which is rolled back.
 */
final class WorkflowCases
{
    private const CATEGORY = 'workflow';

    private const TASK_FIELDS = ['title' => '問い合わせの要約（編集）', 'description' => '問い合わせ内容を要約する。', 'action_type' => 'text.summarize', 'steps' => ['内容を読む'], 'priority' => 'low', 'target_data' => '先週の問い合わせ', 'impact_summary' => '要約のみ'];

    /**
     * @return list<ClosureCase>
     */
    public static function cases(): array
    {
        return [
            new ClosureCase('ST-01', self::CATEGORY, '通常の業務依頼', '下書きのワークフローとタスクが保存される', function (SelfTestContext $context): CaseOutcome {
                $creator = $context->temporaryUser('member');
                $workflow = $context->draftWorkflow($creator);
                $tasks = $workflow === null ? collect() : $context->tasks($workflow);

                return CaseOutcome::all([
                    'workflow_created' => $workflow !== null,
                    'is_draft' => $workflow?->status === WorkflowStatus::Draft,
                    'has_tasks' => $tasks->count() >= 1,
                    'first_revision' => $workflow !== null && $context->revision($workflow)->revision_no === 1,
                    'tasks_allowed' => $tasks->every(fn ($task) => $task->policy_decision === 'allowed'),
                    'masked_input_kept' => $workflow?->source_input_masked === SelfTestContext::INPUT,
                ], '下書き・リビジョン 1・タスクあり', ['tasks' => $tasks->count()]);
            }),

            new ClosureCase('ST-08', self::CATEGORY, '未承認のワークフローの実行', '状態遷移と実行前の再検証が拒否する', function (SelfTestContext $context): CaseOutcome {
                $creator = $context->temporaryUser('member');
                $workflow = $context->draftWorkflow($creator);
                if ($workflow === null) {
                    return CaseOutcome::of(false, 'no workflow');
                }

                $invalidState = false;
                try {
                    WorkflowStateMachine::next($workflow->status, WorkflowEvent::Execute);
                } catch (WorkflowConflictException) {
                    $invalidState = true;
                }

                return CaseOutcome::all([
                    'state_machine_refuses' => $invalidState,
                    'verifier_refuses' => ExecutionVerifier::refusal($workflow, $context->revision($workflow), null, $context->tasks($workflow)) === ExecutionVerifier::APPROVAL_NOT_VALID,
                ], '拒否（APPROVAL_NOT_VALID）', ['status' => $workflow->status->value]);
            }),

            new ClosureCase('ST-09', self::CATEGORY, '承認後の内容の変更', '下書きに戻り、古い承認では実行できない', function (SelfTestContext $context): CaseOutcome {
                $creator = $context->temporaryUser('member');
                $workflow = $context->draftWorkflow($creator);
                if ($workflow === null) {
                    return CaseOutcome::of(false, 'no workflow');
                }

                $context->submit($creator, $workflow);
                $context->approve($context->admin, $workflow);
                $approvedRevision = $context->revision($context->workflow($workflow->id));
                $approval = Approval::query()->where('workflow_revision_id', $approvedRevision->id)->first();

                $task = $context->tasks($workflow)->firstOrFail();
                $context->editTask($creator, $workflow, $task, self::TASK_FIELDS);
                $edited = $context->workflow($workflow->id);
                $newRevision = $context->revision($edited);

                return CaseOutcome::all([
                    'approved_first' => $approval !== null && $approval->decision === Approval::APPROVED,
                    'back_to_draft' => $edited->status === WorkflowStatus::Draft,
                    'new_revision' => $newRevision->revision_no === $approvedRevision->revision_no + 1,
                    'hash_changed' => $newRevision->plan_hash !== $approvedRevision->plan_hash,
                    'old_approval_cannot_run' => ExecutionVerifier::refusal($edited, $newRevision, $approval, $context->tasks($edited)) === ExecutionVerifier::APPROVAL_NOT_VALID,
                ], '下書きに戻り、再承認が必要', ['revision_no' => $newRevision->revision_no]);
            }),

            new ClosureCase('ST-16', self::CATEGORY, '禁止された操作を含むワークフローの提出', '提出が拒否される（FORBIDDEN_ACTION_PRESENT）', function (SelfTestContext $context): CaseOutcome {
                $creator = $context->temporaryUser('member');
                $workflow = $context->draftWorkflow($creator, MockScenario::ForbiddenAction);
                if ($workflow === null) {
                    return CaseOutcome::of(false, 'no workflow');
                }

                return CaseOutcome::all([
                    'marked_forbidden' => ApprovalEligibility::hasForbiddenAction($context->tasks($workflow)),
                    'submit_refused' => self::submitRefusal($context, $creator, $workflow) === ApprovalEligibility::FORBIDDEN_ACTION_PRESENT,
                    'still_draft' => $context->workflow($workflow->id)->status === WorkflowStatus::Draft,
                ], '提出を拒否', ['tasks' => $context->tasks($workflow)->count()]);
            }),

            new ClosureCase('ST-17', self::CATEGORY, '編集で操作を禁止されたものに変更', 'forbidden と判定され、提出できない', function (SelfTestContext $context): CaseOutcome {
                $creator = $context->temporaryUser('member');
                $workflow = $context->draftWorkflow($creator);
                if ($workflow === null) {
                    return CaseOutcome::of(false, 'no workflow');
                }

                $task = $context->tasks($workflow)->firstOrFail();
                $context->editTask($creator, $workflow, $task, [...self::TASK_FIELDS, 'action_type' => 'email.send']);
                $edited = $context->tasks($workflow)->firstOrFail();

                return CaseOutcome::all([
                    'marked_forbidden' => $edited->policy_decision === 'forbidden',
                    'submit_refused' => self::submitRefusal($context, $creator, $workflow) === ApprovalEligibility::FORBIDDEN_ACTION_PRESENT,
                ], 'forbidden、提出を拒否', ['action_type' => $edited->action_type]);
            }),

            new ClosureCase('ST-20', self::CATEGORY, '古い plan_hash での承認', '承認は最新の計画のハッシュにのみ一致する', function (SelfTestContext $context): CaseOutcome {
                $creator = $context->temporaryUser('member');
                $workflow = $context->draftWorkflow($creator);
                if ($workflow === null) {
                    return CaseOutcome::of(false, 'no workflow');
                }

                $first = $context->revision($workflow);
                $context->editTask($creator, $workflow, $context->tasks($workflow)->firstOrFail(), self::TASK_FIELDS);
                $second = $context->revision($context->workflow($workflow->id));

                return CaseOutcome::all([
                    'old_hash_does_not_match' => ! PlanHasher::matches($second->plan_snapshot, $first->plan_hash),
                    'current_hash_matches' => PlanHasher::matches($second->plan_snapshot, $second->plan_hash),
                    'plan_intact' => ApprovalEligibility::planIsIntact($context->workflow($workflow->id), $second, $context->tasks($workflow)),
                ], '古いハッシュは不一致、現行は一致', ['revision_no' => $second->revision_no]);
            }),

            new ClosureCase('ST-21', self::CATEGORY, '自己承認（Policy と DB トリガー）', 'アプリでも DB でも拒否される', function (SelfTestContext $context): CaseOutcome {
                $creatorAdmin = $context->temporaryUser('admin');
                $workflow = $context->draftWorkflow($creatorAdmin);
                if ($workflow === null) {
                    return CaseOutcome::of(false, 'no workflow');
                }
                $context->submit($creatorAdmin, $workflow);
                $pending = $context->workflow($workflow->id);
                $revision = $context->revision($pending);

                $sqlState = $context->attempt(fn () => DB::table('approvals')->insert(self::approvalRow($pending, $revision->id, $revision->plan_hash, $creatorAdmin)));

                return CaseOutcome::all([
                    'policy_refuses' => Gate::forUser($creatorAdmin)->inspect('approve', $pending)->code() === 'SELF_APPROVAL_FORBIDDEN',
                    'eligibility_refuses' => ApprovalEligibility::cannotApproveReason($creatorAdmin, $pending, $revision, $context->tasks($pending)) === ApprovalEligibility::SELF_CREATED,
                    'database_refuses' => $sqlState !== null,
                    'nothing_inserted' => Approval::query()->where('workflow_revision_id', $revision->id)->doesntExist(),
                ], 'Policy と DB が拒否', ['sqlstate' => $sqlState]);
            }),

            new ClosureCase('ST-22', self::CATEGORY, '二重実行（同一キーの再送・別キー・DB の一意制約）', '実行は 1 件のみ', function (SelfTestContext $context): CaseOutcome {
                $creator = $context->temporaryUser('member');
                $workflow = $context->draftWorkflow($creator);
                if ($workflow === null) {
                    return CaseOutcome::of(false, 'no workflow');
                }
                $context->submit($creator, $workflow);
                $context->approve($context->admin, $workflow);

                $key = (string) Str::uuid7();
                $first = $context->requestExecution($creator, $workflow, $key);
                $resent = $context->requestExecution($creator, $workflow, $key);
                $running = $context->workflow($workflow->id);
                $revision = $context->revision($running);
                $approval = Approval::query()->where('workflow_revision_id', $revision->id)->first();

                $sameApproval = $context->attempt(fn () => DB::table('workflow_executions')->insert(self::executionRow($running, $revision->id, (string) $approval?->id, $creator)));

                return CaseOutcome::all([
                    'first_queued' => $first->status === WorkflowExecution::STATUS_QUEUED,
                    'resend_returns_same' => $resent->id === $first->id,
                    'verifier_refuses_another' => ExecutionVerifier::refusal($running, $revision, $approval, $context->tasks($running)) === ExecutionVerifier::EXECUTION_ALREADY_EXISTS,
                    'database_refuses_same_approval' => $sameApproval === '23505',
                    'one_execution' => WorkflowExecution::query()->where('workflow_id', $running->id)->count() === 1,
                ], '実行は 1 件', ['sqlstate' => $sameApproval]);
            }),

            new ClosureCase('ST-30', self::CATEGORY, 'AI 利用上限の超過', '上限に達すると拒否され、AI は呼ばれない', function (SelfTestContext $context): CaseOutcome {
                $user = $context->temporaryUser('member');
                $ledger = app(AiUsageLedger::class);
                $before = $ledger->refusalFor($user);

                $settings = OrganizationSetting::query()->whereKey($context->organizationId)->first()
                    ?? (new OrganizationSetting)->forceFill(['organization_id' => $context->organizationId, ...OrganizationSetting::DEFAULTS]);
                $settings->forceFill(['user_daily_request_limit' => 1])->save();

                (new AiUsageLog)->forceFill([
                    'user_id' => $user->id,
                    'provider' => 'mock',
                    'model' => null,
                    'purpose' => AiUsageLog::PURPOSE_TASK_GENERATION,
                    'status' => AiUsageLog::STATUS_SUCCESS,
                    'total_tokens' => 1,
                ])->save();

                return CaseOutcome::all([
                    'allowed_before' => $before === null,
                    'refused_at_limit' => $ledger->refusalFor($user) === AiUsageLedger::USER_DAILY_LIMIT,
                ], '上限で拒否（USER_DAILY_LIMIT）', ['limit' => 1]);
            }),

            new ClosureCase('ST-37', self::CATEGORY, '承認できる管理者がいない組織', '承認者不在と判定され、実行できない', function (SelfTestContext $context): CaseOutcome {
                $organization = $context->temporaryOrganization();
                $onlyAdmin = $context->temporaryUser('admin', $organization->id);
                $workflow = new Workflow;
                $workflow->forceFill(['id' => (string) Str::uuid7(), 'organization_id' => $organization->id, 'created_by' => $onlyAdmin->id, 'status' => WorkflowStatus::Pending, 'title' => 'self-test']);

                $none = ApprovalEligibility::approverAvailable($workflow);
                $context->temporaryUser('admin', $organization->id);
                $another = ApprovalEligibility::approverAvailable($workflow);

                return CaseOutcome::all([
                    'no_approver_when_alone' => $none === false,
                    'approver_when_another_admin' => $another === true,
                    'cannot_execute_unapproved' => ExecutionVerifier::refusal($workflow, null, null, new EloquentCollection) === ExecutionVerifier::APPROVAL_NOT_VALID,
                ], '承認者不在、実行不可', ['checks' => 3]);
            }),

            new ClosureCase('ST-38', self::CATEGORY, 'auditor・member による承認の直接の INSERT', 'DB トリガーが拒否する', function (SelfTestContext $context): CaseOutcome {
                $creator = $context->temporaryUser('member');
                $workflow = $context->draftWorkflow($creator);
                if ($workflow === null) {
                    return CaseOutcome::of(false, 'no workflow');
                }
                $context->submit($creator, $workflow);
                $pending = $context->workflow($workflow->id);
                $revision = $context->revision($pending);

                $byMember = $context->attempt(fn () => DB::table('approvals')->insert(self::approvalRow($pending, $revision->id, $revision->plan_hash, $context->temporaryUser('member'))));
                $byAuditor = $context->attempt(fn () => DB::table('approvals')->insert(self::approvalRow($pending, $revision->id, $revision->plan_hash, $context->temporaryUser('auditor'))));

                return CaseOutcome::all([
                    'member_refused' => $byMember !== null,
                    'auditor_refused' => $byAuditor !== null,
                    'nothing_inserted' => Approval::query()->where('workflow_revision_id', $revision->id)->doesntExist(),
                ], 'DB が拒否', ['sqlstate_member' => $byMember, 'sqlstate_auditor' => $byAuditor]);
            }),
        ];
    }

    private static function submitRefusal(SelfTestContext $context, User $creator, Workflow $workflow): ?string
    {
        try {
            $context->submit($creator, $workflow);
        } catch (WorkflowConflictException $exception) {
            return $exception->problemCode;
        }

        return null;
    }

    /**
     * @return array<string, mixed>
     */
    private static function approvalRow(Workflow $workflow, string $revisionId, string $planHash, User $decider): array
    {
        return [
            'id' => (string) Str::uuid7(),
            'organization_id' => $workflow->organization_id,
            'workflow_id' => $workflow->id,
            'workflow_revision_id' => $revisionId,
            'plan_hash' => $planHash,
            'decision' => Approval::APPROVED,
            'decided_by' => $decider->id,
            'acknowledged_risks' => true,
            'created_at' => now()->toIso8601String(),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function executionRow(Workflow $workflow, string $revisionId, string $approvalId, User $requester): array
    {
        return [
            'id' => (string) Str::uuid7(),
            'organization_id' => $workflow->organization_id,
            'workflow_id' => $workflow->id,
            'approval_id' => $approvalId,
            'workflow_revision_id' => $revisionId,
            'idempotency_key' => (string) Str::uuid7(),
            'requested_by' => $requester->id,
            'status' => WorkflowExecution::STATUS_QUEUED,
            'created_at' => now()->toIso8601String(),
            'updated_at' => now()->toIso8601String(),
        ];
    }
}
