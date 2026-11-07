<?php

use App\Models\Organization;
use App\Models\User;
use Illuminate\Database\Connection;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Str;

/*
| docs/database-design.md §3.5 to §3.9, §5. What the database itself refuses, as the application role,
| whatever the application does. ST-21 and ST-38 (the database part).
*/

uses(DatabaseTransactions::class);

beforeEach(function () {
    $this->org = Organization::factory()->create();
    $this->creator = userIn($this->org->id);
    $this->admin = userIn($this->org->id, 'admin');
    $this->workflow = workflowOf($this->creator);
    $this->otherOrg = Organization::factory()->create();
    $this->otherUser = userIn($this->otherOrg->id, 'admin');
    $this->otherWorkflow = workflowOf($this->otherUser);
});

function expectDbError(Closure $statement, string $sqlState): void
{
    $error = dbError(appDb(), $statement);

    expect($error)->not->toBeNull()->and($error->getCode())->toBe($sqlState);
}

it('accepts a complete and valid chain of rows', function () {
    $revision = insertRevision(appDb(), $this->workflow);
    insertTask(appDb(), $this->workflow);
    $approval = insertApproval(appDb(), $this->workflow, $revision, $this->admin->id);
    insertExecution(appDb(), $this->workflow, $revision, $approval);

    appDb()->table('workflows')->where('id', $this->workflow->id)->update(['current_revision_id' => $revision]);
    appDb()->statement('SET CONSTRAINTS ALL IMMEDIATE');

    expect(appDb()->table('workflow_executions')->count())->toBe(1);
});

// ---- Append-only ------------------------------------------------------------------------------

it('does not let the application role change or delete revisions and approvals', function (string $table, string $statement) {
    $revision = insertRevision(appDb(), $this->workflow);
    insertApproval(appDb(), $this->workflow, $revision, $this->admin->id);

    expectDbError(fn (Connection $db) => $db->statement(sprintf($statement, $table)), '42501');
})->with(['workflow_revisions', 'approvals'])->with([
    'update' => ['UPDATE %s SET created_at = now()'],
    'delete' => ['DELETE FROM %s'],
    'truncate' => ['TRUNCATE %s CASCADE'],
]);

// ---- ST-21 and ST-38: who may decide ----------------------------------------------------------

it('ST-21: refuses an approval by the creator, even an admin', function () {
    $adminWorkflow = workflowOf($this->admin);
    $revision = insertRevision(appDb(), $adminWorkflow);

    expectDbError(fn (Connection $db) => insertApproval($db, $adminWorkflow, $revision, $this->admin->id), '42501');
})->group('security');

it('ST-38: refuses a decision by anyone but an active admin', function (string $role, array $attributes) {
    $revision = insertRevision(appDb(), $this->workflow);
    $decider = userIn($this->org->id, $role, $attributes);

    expectDbError(fn (Connection $db) => insertApproval($db, $this->workflow, $revision, $decider->id), '42501');
})->with([
    'member' => ['member', []],
    'auditor' => ['auditor', []],
    'inactive admin' => ['admin', ['is_active' => false]],
])->group('security');

it('accepts a decision by a locked admin: a lock does not take away approval rights', function () {
    $revision = insertRevision(appDb(), $this->workflow);
    $locked = userIn($this->org->id, 'admin', ['locked_until' => now()->addMinutes(15)]);

    insertApproval(appDb(), $this->workflow, $revision, $locked->id);

    expect(appDb()->table('approvals')->count())->toBe(1);
});

it('refuses a second decision on the same revision', function (string $decision) {
    $revision = insertRevision(appDb(), $this->workflow);
    insertApproval(appDb(), $this->workflow, $revision, $this->admin->id);
    $second = userIn($this->org->id, 'admin');

    expectDbError(fn (Connection $db) => insertApproval($db, $this->workflow, $revision, $second->id, ['decision' => $decision]), '23505');
})->with(['approved', 'rejected']);

// ---- Staying inside the organization and the workflow -----------------------------------------

it('refuses rows that cross an organization or a workflow', function (Closure $statement) {
    expectDbError(fn (Connection $db) => $statement->call($this, $db), '23503');
})->with([
    'workflow created by a user of another organization' => [function (Connection $db) {
        $db->table('workflows')->insert([
            'id' => (string) Str::uuid7(), 'organization_id' => $this->org->id, 'created_by' => $this->otherUser->id,
            'title' => 'T', 'source_input_masked' => 'S', 'status' => 'draft',
            'created_at' => now()->toIso8601String(), 'updated_at' => now()->toIso8601String(),
        ]);
    }],
    'revision with another organization' => [function (Connection $db) {
        insertRevision($db, $this->workflow, ['organization_id' => $this->otherOrg->id]);
    }],
    'revision created by a user of another organization' => [function (Connection $db) {
        insertRevision($db, $this->workflow, ['created_by' => $this->otherUser->id]);
    }],
    'task with another organization' => [function (Connection $db) {
        insertTask($db, $this->workflow, ['organization_id' => $this->otherOrg->id]);
    }],
    'approval of a revision of another workflow' => [function (Connection $db) {
        $revision = insertRevision($db, workflowOf($this->creator));
        insertApproval($db, $this->workflow, $revision, $this->admin->id);
    }],
    'approval with another organization' => [function (Connection $db) {
        $revision = insertRevision($db, $this->workflow);
        // An admin of that organization, so that the trigger passes and the foreign key decides.
        insertApproval($db, $this->workflow, $revision, $this->otherUser->id, ['organization_id' => $this->otherOrg->id]);
    }],
    'execution of a revision of another workflow' => [function (Connection $db) {
        $revision = insertRevision($db, $this->workflow);
        $approval = insertApproval($db, $this->workflow, $revision, $this->admin->id);
        $other = workflowOf($this->creator);
        insertExecution($db, $this->workflow, insertRevision($db, $other), $approval);
    }],
    'execution with an approval of another revision' => [function (Connection $db) {
        $revision = insertRevision($db, $this->workflow);
        $approval = insertApproval($db, $this->workflow, $revision, $this->admin->id);
        insertExecution($db, $this->workflow, insertRevision($db, $this->workflow, ['revision_no' => 2]), $approval);
    }],
    'execution requested by a user of another organization' => [function (Connection $db) {
        $revision = insertRevision($db, $this->workflow);
        $approval = insertApproval($db, $this->workflow, $revision, $this->admin->id);
        insertExecution($db, $this->workflow, $revision, $approval, ['requested_by' => $this->otherUser->id]);
    }],
]);

it('refuses a decider of another organization, before any foreign key', function () {
    $revision = insertRevision(appDb(), $this->workflow);

    expectDbError(fn (Connection $db) => insertApproval($db, $this->workflow, $revision, $this->otherUser->id), '42501');
});

it('refuses pointing a workflow at a revision of another workflow, at the latest on commit', function () {
    $revision = insertRevision(appDb(), workflowOf($this->creator));

    expectDbError(function (Connection $db) use ($revision) {
        $db->table('workflows')->where('id', $this->workflow->id)->update(['current_revision_id' => $revision]);
        $db->statement('SET CONSTRAINTS ALL IMMEDIATE');
    }, '23503');
});

it('does not let the application role move a row or change who created it', function (string $statement) {
    expectDbError(fn (Connection $db) => $db->statement($statement), '42501');
})->with([
    'workflow organization' => ['UPDATE workflows SET organization_id = id'],
    'workflow id' => ['UPDATE workflows SET id = id'],
    'workflow creator' => ['UPDATE workflows SET created_by = id'],
    'workflow source' => ["UPDATE workflows SET source_input_masked = ''"],
    'task organization' => ['UPDATE workflow_tasks SET organization_id = id'],
    'task workflow' => ['UPDATE workflow_tasks SET workflow_id = id'],
    'execution approval' => ['UPDATE workflow_executions SET approval_id = id'],
    'execution key' => ["UPDATE workflow_executions SET idempotency_key = ''"],
    'execution requester' => ['UPDATE workflow_executions SET requested_by = id'],
    'delete a workflow' => ['DELETE FROM workflows'],
    'delete an execution' => ['DELETE FROM workflow_executions'],
]);

// ---- Execution ---------------------------------------------------------------------------------

it('uses an approval for one execution only', function () {
    $revision = insertRevision(appDb(), $this->workflow);
    $approval = insertApproval(appDb(), $this->workflow, $revision, $this->admin->id);
    insertExecution(appDb(), $this->workflow, $revision, $approval, ['status' => 'completed']);

    expectDbError(fn (Connection $db) => insertExecution($db, $this->workflow, $revision, $approval), '23505');
});

it('runs one execution of a workflow at a time', function (string $status) {
    $first = insertRevision(appDb(), $this->workflow);
    $firstExecution = insertExecution(appDb(), $this->workflow, $first, insertApproval(appDb(), $this->workflow, $first, $this->admin->id), ['status' => $status]);
    $second = insertRevision(appDb(), $this->workflow, ['revision_no' => 2]);
    $secondApproval = insertApproval(appDb(), $this->workflow, $second, $this->admin->id);

    expectDbError(fn (Connection $db) => insertExecution($db, $this->workflow, $second, $secondApproval), '23505');

    appDb()->table('workflow_executions')->where('id', $firstExecution)->update(['status' => 'completed']);
    insertExecution(appDb(), $this->workflow, $second, $secondApproval);

    expect(appDb()->table('workflow_executions')->count())->toBe(2);
})->with(['queued', 'running']);

it('refuses an idempotency key used in the organization, and allows it in another', function () {
    $revision = insertRevision(appDb(), $this->workflow);
    insertExecution(appDb(), $this->workflow, $revision, insertApproval(appDb(), $this->workflow, $revision, $this->admin->id), ['idempotency_key' => 'same', 'status' => 'completed']);
    $second = insertRevision(appDb(), $this->workflow, ['revision_no' => 2]);
    $secondApproval = insertApproval(appDb(), $this->workflow, $second, $this->admin->id);

    expectDbError(fn (Connection $db) => insertExecution($db, $this->workflow, $second, $secondApproval, ['idempotency_key' => 'same']), '23505');

    $otherAdmin = userIn($this->otherOrg->id, 'admin');
    $otherRevision = insertRevision(appDb(), $this->otherWorkflow);
    insertExecution(appDb(), $this->otherWorkflow, $otherRevision, insertApproval(appDb(), $this->otherWorkflow, $otherRevision, $otherAdmin->id), ['idempotency_key' => 'same']);

    expect(appDb()->table('workflow_executions')->where('idempotency_key', 'same')->count())->toBe(2);
});

// ---- Shape -------------------------------------------------------------------------------------

it('refuses values outside the design', function (Closure $statement) {
    expectDbError(fn (Connection $db) => $statement->call($this, $db), '23514');
})->with([
    'unknown status' => [fn (Connection $db) => $db->statement("UPDATE workflows SET status = 'done'")],
    'negative lock version' => [fn (Connection $db) => $db->statement('UPDATE workflows SET lock_version = -1')],
    'unknown severity' => [fn (Connection $db) => $db->statement("UPDATE workflows SET max_severity = 'none'")],
    'uppercase plan hash' => [fn (Connection $db) => insertRevision($db, $this->workflow, ['plan_hash' => str_repeat('A', 64)])],
    'short plan hash' => [fn (Connection $db) => insertRevision($db, $this->workflow, ['plan_hash' => str_pad('a', 64, ' ')])],
    'revision zero' => [fn (Connection $db) => insertRevision($db, $this->workflow, ['revision_no' => 0])],
    'snapshot not an object' => [fn (Connection $db) => insertRevision($db, $this->workflow, ['plan_snapshot' => '[]'])],
    'unknown change type' => [fn (Connection $db) => insertRevision($db, $this->workflow, ['change_type' => 'other'])],
    'position 0' => [fn (Connection $db) => insertTask($db, $this->workflow, ['position' => 0])],
    'position 11' => [fn (Connection $db) => insertTask($db, $this->workflow, ['position' => 11])],
    'steps not a list' => [fn (Connection $db) => insertTask($db, $this->workflow, ['steps' => '{}'])],
    'permissions not a list' => [fn (Connection $db) => insertTask($db, $this->workflow, ['derived_permissions' => '{}'])],
    'unknown priority' => [fn (Connection $db) => insertTask($db, $this->workflow, ['priority' => 'urgent'])],
    'unknown policy decision' => [fn (Connection $db) => insertTask($db, $this->workflow, ['policy_decision' => 'maybe'])],
]);

it('requires the enum columns', function (Closure $statement) {
    expectDbError(fn (Connection $db) => $statement->call($this, $db), '23502');
})->with([
    'workflow status' => [fn (Connection $db) => $db->statement('UPDATE workflows SET status = NULL')],
    'change type' => [fn (Connection $db) => insertRevision($db, $this->workflow, ['change_type' => null])],
    'priority' => [fn (Connection $db) => insertTask($db, $this->workflow, ['priority' => null])],
    'policy decision' => [fn (Connection $db) => insertTask($db, $this->workflow, ['policy_decision' => null])],
]);

// ---- The scan of a revision (step 2-3; older rows are in MigrationTest) ---------------------------

it('refuses a new revision with no scan', function () {
    expectDbError(fn (Connection $db) => insertRevision($db, $this->workflow, ['scan_id' => null, 'scan_decision' => null]), '23514');
});

it('refuses a revision whose decision is not what its scan decided', function () {
    $scan = insertScan(appDb(), $this->workflow->organization_id, ['decision' => 'block', 'block_reason' => 'SECRET_DETECTED']);

    expectDbError(fn (Connection $db) => insertRevision($db, $this->workflow, ['scan_id' => $scan, 'scan_decision' => 'allow']), '23503');
});

it('refuses a revision that points at the scan of another organization', function () {
    $other = insertOrganization(appDb());
    $scan = insertScan(appDb(), $other);

    expectDbError(fn (Connection $db) => insertRevision($db, $this->workflow, ['scan_id' => $scan, 'scan_decision' => 'allow']), '23503');
});

it('refuses half of a scan result', function (array $values) {
    expectDbError(fn (Connection $db) => insertRevision($db, $this->workflow, $values), '23514');
})->with([
    'a decision with no scan' => [['scan_decision' => 'allow']],
    'a scan with no decision' => [['scan_id' => '0193a000-0000-7000-8000-000000000001']],
]);

// ---- Tasks -------------------------------------------------------------------------------------

it('keeps positions unique, and lets them be swapped inside a transaction', function () {
    $first = insertTask(appDb(), $this->workflow, ['position' => 1]);
    $second = insertTask(appDb(), $this->workflow, ['position' => 2]);

    expectDbError(fn (Connection $db) => insertTask($db, $this->workflow, ['position' => 1]), '23505');

    appDb()->transaction(function (Connection $db) use ($first, $second) {
        $db->statement('SET CONSTRAINTS workflow_tasks_position_unique DEFERRED');
        $db->table('workflow_tasks')->where('id', $first)->update(['position' => 2]);
        $db->table('workflow_tasks')->where('id', $second)->update(['position' => 1]);
        $db->statement('SET CONSTRAINTS workflow_tasks_position_unique IMMEDIATE');
    });

    expect(appDb()->table('workflow_tasks')->where('id', $first)->value('position'))->toBe(2);
});

it('lets the application role delete a task, the only row it can delete', function () {
    $task = insertTask(appDb(), $this->workflow);

    expect(appDb()->table('workflow_tasks')->where('id', $task)->delete())->toBe(1);
});

it('keeps the users key usable by the existing users', function () {
    expect(User::query()->where('organization_id', $this->org->id)->count())->toBe(2);
});
