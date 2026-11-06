<?php

use App\Models\Organization;
use App\Models\User;
use App\Models\Workflow;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Gate;

/*
| ST-06, ST-12, ST-21, ST-23 and ST-37 at the level of the policy (docs/api-design.md §2,
| docs/security-design.md §9.3, §12, §13). allow, 404, 403 and the codes are written out by hand.
*/

uses(DatabaseTransactions::class);

const WORKFLOW_ABILITIES = ['view', 'update', 'submit', 'reopen', 'approve', 'reject', 'execute'];

const ALLOW = 'allow';

const HIDDEN = '404';

const FORBIDDEN = '403 FORBIDDEN';

const NOT_APPROVER = '403 APPROVER_ROLE_REQUIRED';

const SELF_APPROVAL = '403 SELF_APPROVAL_FORBIDDEN';

function verdict(User $user, string $ability, Workflow|string $subject): string
{
    $response = Gate::forUser($user)->inspect($ability, $subject);

    return match (true) {
        $response->allowed() => ALLOW,
        $response->status() === 404 => HIDDEN,
        default => '403 '.$response->code(),
    };
}

/**
 * @param  array<int, string>  $expected  in the order of WORKFLOW_ABILITIES
 */
function assertVerdicts(User $user, Workflow $workflow, array $expected): void
{
    expect(array_map(fn (string $ability) => verdict($user, $ability, $workflow), WORKFLOW_ABILITIES))->toBe($expected);
}

beforeEach(function () {
    $this->org = Organization::factory()->create();
    $this->otherOrg = Organization::factory()->create();
    $this->member = userIn($this->org->id);
    $this->admin = userIn($this->org->id, 'admin');
    $this->memberWorkflow = workflowOf($this->member);
    $this->adminWorkflow = workflowOf($this->admin);
});

it('the creator, as a member', function () {
    assertVerdicts($this->member, $this->memberWorkflow, [ALLOW, ALLOW, ALLOW, ALLOW, NOT_APPROVER, NOT_APPROVER, ALLOW]);
});

it('the creator, as an admin: everything except deciding', function () {
    assertVerdicts($this->admin, $this->adminWorkflow, [ALLOW, ALLOW, ALLOW, ALLOW, SELF_APPROVAL, SELF_APPROVAL, ALLOW]);
});

it('another admin: sees, decides and executes, but does not edit', function () {
    assertVerdicts($this->admin, $this->memberWorkflow, [ALLOW, FORBIDDEN, FORBIDDEN, FORBIDDEN, ALLOW, ALLOW, ALLOW]);
});

it('ST-12: another member sees nothing', function () {
    assertVerdicts(userIn($this->org->id), $this->memberWorkflow, array_fill(0, 7, HIDDEN));
});

it('ST-06: an auditor sees, and changes nothing', function () {
    assertVerdicts(userIn($this->org->id, 'auditor'), $this->memberWorkflow, [ALLOW, FORBIDDEN, FORBIDDEN, FORBIDDEN, NOT_APPROVER, NOT_APPROVER, FORBIDDEN]);
});

it('ST-23: every role of another organization sees nothing', function (string $role) {
    $outsider = userIn($this->otherOrg->id, $role);

    assertVerdicts($outsider, $this->memberWorkflow, array_fill(0, 7, HIDDEN));
    assertVerdicts($outsider, $this->adminWorkflow, array_fill(0, 7, HIDDEN));
})->with(['admin', 'member', 'auditor']);

it('the role comes before ownership: a creator who became an auditor changes nothing', function () {
    $this->member->forceFill(['role' => 'auditor'])->save();

    assertVerdicts($this->member, $this->memberWorkflow, [ALLOW, FORBIDDEN, FORBIDDEN, FORBIDDEN, NOT_APPROVER, NOT_APPROVER, FORBIDDEN]);
});

it('an admin who became a member decides nothing and loses sight of the others', function () {
    $this->admin->forceFill(['role' => 'member'])->save();

    assertVerdicts($this->admin, $this->memberWorkflow, array_fill(0, 7, HIDDEN));
    assertVerdicts($this->admin, $this->adminWorkflow, [ALLOW, ALLOW, ALLOW, ALLOW, NOT_APPROVER, NOT_APPROVER, ALLOW]);
});

it('a user made inactive during the request can do nothing, even as creator', function () {
    $this->member->forceFill(['is_active' => false])->save();

    assertVerdicts($this->member, $this->memberWorkflow, array_fill(0, 7, FORBIDDEN));
    expect(verdict($this->member, 'create', Workflow::class))->toBe(FORBIDDEN)
        ->and(verdict($this->member, 'viewAny', Workflow::class))->toBe(FORBIDDEN);
});

it('a lock takes nothing away: approval and execution stay possible (T-33)', function () {
    $this->admin->forceFill(['locked_until' => now()->addMinutes(15)])->save();

    assertVerdicts($this->admin, $this->memberWorkflow, [ALLOW, FORBIDDEN, FORBIDDEN, FORBIDDEN, ALLOW, ALLOW, ALLOW]);
});

it('ST-37: no admin in the organization means nobody can decide, and nothing overrides it', function () {
    $alone = Organization::factory()->create();
    $onlyAdmin = userIn($alone->id, 'admin');
    $member = userIn($alone->id);
    $auditor = userIn($alone->id, 'auditor');
    $workflow = workflowOf($onlyAdmin);

    foreach ([$onlyAdmin, $member, $auditor] as $user) {
        expect(verdict($user, 'approve', $workflow))->not->toBe(ALLOW)
            ->and(verdict($user, 'reject', $workflow))->not->toBe(ALLOW);
    }
});

it('who may create a workflow', function (string $role, string $expected) {
    expect(verdict(userIn($this->org->id, $role), 'create', Workflow::class))->toBe($expected);
})->with([
    'admin' => ['admin', ALLOW],
    'member' => ['member', ALLOW],
    'auditor' => ['auditor', FORBIDDEN],
]);

it('every active role may list, and the list itself is limited by the scope', function (string $role) {
    expect(verdict(userIn($this->org->id, $role), 'viewAny', Workflow::class))->toBe(ALLOW);
})->with(['admin', 'member', 'auditor']);

it('denies an ability the policy does not define', function () {
    expect(Gate::forUser($this->admin)->allows('forceExecute', $this->memberWorkflow))->toBeFalse();
});
