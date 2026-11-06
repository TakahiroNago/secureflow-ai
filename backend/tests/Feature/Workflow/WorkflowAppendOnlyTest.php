<?php

use App\Models\Organization;
use Illuminate\Database\Connection;

/*
| docs/database-design.md §5. The trigger is the second layer, for a role that has the table privileges.
| The owner uses its own connection, so the rows have to be committed for it to see them.
*/

beforeEach(function () {
    $this->org = Organization::factory()->create();
    $this->users = [userIn($this->org->id), userIn($this->org->id, 'admin')];
    $workflow = workflowOf($this->users[0]);
    $revision = insertRevision(appDb(), $workflow);
    insertApproval(appDb(), $workflow, $revision, $this->users[1]->id);
});

afterEach(function () {
    resetWorkflowTables();

    foreach ($this->users as $user) {
        ownerDb()->table('users')->where('id', $user->id)->delete();
    }
    ownerDb()->table('organizations')->where('id', $this->org->id)->delete();
});

it('stops even the owner with the trigger', function (string $table, string $statement) {
    $error = dbError(ownerDb(), fn (Connection $db) => $db->statement(sprintf($statement, $table)));

    expect($error)->not->toBeNull()
        ->and($error->getCode())->toBe('42501')
        ->and($error->getMessage())->toContain('is append-only');

    expect(appDb()->table($table)->count())->toBe(1);
})->with(['workflow_revisions', 'approvals'])->with([
    'update' => ['UPDATE %s SET created_at = now()'],
    'delete' => ['DELETE FROM %s'],
    'truncate' => ['TRUNCATE %s CASCADE'],
]);
