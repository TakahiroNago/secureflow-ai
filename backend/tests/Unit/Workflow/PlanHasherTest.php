<?php

use App\Domain\Workflow\InvalidPlanException;
use App\Domain\Workflow\PlanHasher;

/*
| docs/security-design.md §9. The vectors come from tests/Fixtures/generate-plan-hash-vectors.py, an
| implementation that shares nothing with PlanHasher.
*/

function planVectors(): array
{
    return json_decode((string) file_get_contents(__DIR__.'/../../Fixtures/plan-hash-vectors.json'), true, flags: JSON_THROW_ON_ERROR);
}

function validPlan(array $task = [], array $plan = []): array
{
    return [
        'hash_version' => 1,
        'organization_id' => '0193a000-0000-7000-8000-000000000001',
        'workflow_id' => '0193a000-0000-7000-8000-000000000002',
        'revision_no' => 1,
        'policy_version' => '2026.11.1',
        'tasks' => [[
            'position' => 1,
            'title' => 'Title',
            'description' => 'Description',
            'action_type' => 'report.draft',
            'steps' => ['one', 'two'],
            'priority' => 'medium',
            'target_data' => 'Target',
            'impact_summary' => 'Impact',
            'permissions' => ['ai.text.read', 'report.draft.write'],
            'policy_decision' => 'allowed',
            ...$task,
        ]],
        ...$plan,
    ];
}

dataset('vectors', fn () => array_map(fn (array $vector) => [$vector], array_column(planVectors(), null, 'name')));

it('agrees with the independent implementation', function (array $vector) {
    expect(PlanHasher::canonicalJson($vector['plan']))->toBe($vector['canonical'])
        ->and(PlanHasher::hash($vector['plan']))->toBe($vector['hash']);
})->with('vectors');

it('gives the same hash after a jsonb round trip reorders the keys', function (array $vector) {
    $snapshot = PlanHasher::normalize($vector['plan']);

    $reorder = function (array $value) use (&$reorder): array {
        $value = array_map(fn ($item) => is_array($item) ? $reorder($item) : $item, $value);

        if (! array_is_list($value)) {
            uksort($value, fn (string $a, string $b) => [strlen($a), $a] <=> [strlen($b), $b]);
        }

        return $value;
    };

    expect(PlanHasher::matches($reorder($snapshot), $vector['hash']))->toBeTrue()
        ->and(array_keys($reorder($snapshot)))->not->toBe(array_keys($snapshot));
})->with('vectors');

it('is stable: normalizing twice changes nothing', function (array $vector) {
    $once = PlanHasher::normalize($vector['plan']);

    expect(PlanHasher::normalize($once))->toBe($once);
})->with('vectors');

it('changes the hash when anything approved changes', function (array $task, array $plan) {
    expect(PlanHasher::hash(validPlan($task, $plan)))->not->toBe(PlanHasher::hash(validPlan()));
})->with([
    'title' => [['title' => 'Other'], []],
    'description' => [['description' => 'Other'], []],
    'action' => [['action_type' => 'task.create'], []],
    'step text' => [['steps' => ['one', 'changed']], []],
    'step order' => [['steps' => ['two', 'one']], []],
    'priority' => [['priority' => 'high'], []],
    'target' => [['target_data' => 'Other'], []],
    'impact' => [['impact_summary' => 'Other'], []],
    'permissions' => [['permissions' => ['ai.text.read']], []],
    'decision' => [['policy_decision' => 'forbidden'], []],
    'position' => [['position' => 2], []],
    'revision' => [[], ['revision_no' => 2]],
    'policy version' => [[], ['policy_version' => '2026.11.2']],
    'organization' => [[], ['organization_id' => '0193a000-0000-7000-8000-000000000009']],
    'workflow' => [[], ['workflow_id' => '0193a000-0000-7000-8000-000000000009']],
]);

it('does not depend on the order of permissions', function () {
    expect(PlanHasher::hash(validPlan(['permissions' => ['report.draft.write', 'ai.text.read']])))
        ->toBe(PlanHasher::hash(validPlan()));
});

it('separates this hash from others with its prefix', function () {
    $plan = validPlan();

    expect(PlanHasher::hash($plan))->not->toBe(hash('sha256', PlanHasher::canonicalJson($plan)))
        ->and(PlanHasher::hash($plan))->toMatch('/^[0-9a-f]{64}$/');
});

it('refuses a plan that is not exactly the designed shape', function (array $task, array $plan) {
    expect(fn () => PlanHasher::hash(validPlan($task, $plan)))->toThrow(InvalidPlanException::class);
})->with([
    'an extra task field' => [['ai_claimed_permissions' => []], []],
    'an extra plan field' => [[], ['note' => 'x']],
    'a float position' => [['position' => 1.5], []],
    'a string position' => [['position' => '1'], []],
    'a boolean title' => [['title' => true], []],
    'a null title' => [['title' => null], []],
    'a number in steps' => [['steps' => [1]], []],
    'steps as an object' => [['steps' => ['a' => 'b']], []],
    'permissions as a string' => [['permissions' => 'x'], []],
    'NUL in a string' => [['title' => "a\0b"], []],
    'invalid UTF-8' => [['title' => "\xC3\x28"], []],
    'a zero revision' => [[], ['revision_no' => 0]],
    'a string revision' => [[], ['revision_no' => '1']],
    'another hash version' => [[], ['hash_version' => 2]],
    'a malformed organization' => [[], ['organization_id' => 'not-a-uuid']],
    'a trailing newline in a UUID' => [[], ['workflow_id' => "0193a000-0000-7000-8000-000000000002\n"]],
    'tasks as an object' => [[], ['tasks' => ['a' => []]]],
]);

it('refuses a missing field', function () {
    $plan = validPlan();
    unset($plan['tasks'][0]['impact_summary']);

    expect(fn () => PlanHasher::hash($plan))->toThrow(InvalidPlanException::class);
});

it('refuses two tasks in the same position', function () {
    $plan = validPlan();
    $plan['tasks'][] = $plan['tasks'][0];

    expect(fn () => PlanHasher::hash($plan))->toThrow(InvalidPlanException::class);
});

it('does not repeat the content in its error', function () {
    try {
        PlanHasher::hash(validPlan(['title' => "secret-value\0"]));
        $this->fail('Should have been refused.');
    } catch (InvalidPlanException $exception) {
        expect($exception->getMessage())->not->toContain('secret-value');
    }
});

it('matches nothing for a snapshot that cannot be normalized, or a wrong hash', function () {
    expect(PlanHasher::matches(['tampered' => true], str_repeat('0', 64)))->toBeFalse()
        ->and(PlanHasher::matches(validPlan(), str_repeat('0', 64)))->toBeFalse()
        ->and(PlanHasher::matches(validPlan(), PlanHasher::hash(validPlan())))->toBeTrue();
});
