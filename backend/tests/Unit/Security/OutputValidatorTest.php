<?php

use App\Security\Output\InvalidAiOutputException;
use App\Security\Output\OutputValidator;
use App\Security\Policy\PolicyDecision;

/*
| AI-OUT-01. docs/security-design.md §7, the parts of step 1-4: parsing, the schema and the allow list.
*/

function aiTask(array $overrides = []): array
{
    return [
        'title' => '要約',
        'description' => '説明',
        'action_type' => 'text.summarize',
        'steps' => ['手順'],
        'priority' => 'low',
        'requested_permissions' => ['ai.text.read'],
        'target_data' => '対象',
        'impact_summary' => '影響',
        ...$overrides,
    ];
}

function aiOutput(array ...$tasks): string
{
    return json_encode(['tasks' => $tasks], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE);
}

function refusedFor(string $output): InvalidAiOutputException
{
    try {
        (new OutputValidator)->validate($output);
    } catch (InvalidAiOutputException $exception) {
        return $exception;
    }

    throw new RuntimeException('The output was accepted.');
}

it('AI-OUT-01: returns a valid task, with permissions from the catalog', function () {
    $tasks = (new OutputValidator)->validate(aiOutput(aiTask(['action_type' => 'report.draft', 'requested_permissions' => []])));

    expect($tasks)->toHaveCount(1)
        ->and($tasks[0]->title)->toBe('要約')
        ->and($tasks[0]->actionType)->toBe('report.draft')
        ->and($tasks[0]->decision)->toBe(PolicyDecision::Allowed)
        ->and($tasks[0]->permissions)->toBe(['ai.text.read', 'report.draft.write'])
        ->and($tasks[0]->requestedPermissions)->toBe([]);
});

it('AI-OUT-01: marks a forbidden action, and does not refuse it', function (string $type) {
    $tasks = (new OutputValidator)->validate(aiOutput(aiTask(), aiTask(['action_type' => $type])));

    expect($tasks[0]->decision)->toBe(PolicyDecision::Allowed)
        ->and($tasks[1]->decision)->toBe(PolicyDecision::Forbidden);
})->with(['email.send', 'file.delete', 'shell.exec', 'db.query', 'http.request']);

it('AI-OUT-01: refuses what is not JSON', function (string $output) {
    expect(refusedFor($output)->reason)->toBe('malformed_json');
})->with([
    'empty' => '',
    'text' => 'はい、承知しました。',
    'cut off' => '{"tasks": [',
    'a code fence' => "```json\n{\"tasks\":[]}\n```",
    'a trailing comma' => '{"tasks":[],}',
    'invalid UTF-8' => "{\"tasks\":\"\xff\"}",
    'too deep' => str_repeat('[', 9).str_repeat(']', 9),
]);

it('AI-OUT-01: refuses a root that is not an object', function (string $output) {
    expect(refusedFor($output)->reason)->toBe('not_an_object');
})->with(['[]', 'null', '1', '"tasks"', 'true']);

it('AI-OUT-01: refuses a list written as an object, which PHP arrays could not tell apart', function (string $output, string $position) {
    $refused = refusedFor($output);

    expect($refused->reason)->toBe('not_a_list')
        ->and($refused->position)->toBe($position);
})->with([
    'tasks' => [json_encode(['tasks' => (object) ['0' => aiTask()]]), 'tasks'],
    'steps' => [json_encode(['tasks' => [aiTask(['steps' => (object) ['0' => '手順']])]]), 'tasks[0].steps'],
    'permissions' => [json_encode(['tasks' => [aiTask(['requested_permissions' => (object) ['0' => 'a']])]]), 'tasks[0].requested_permissions'],
]);

it('AI-OUT-01: refuses unknown and missing keys', function (string $output, string $reason, string $position) {
    $refused = refusedFor($output);

    expect($refused->reason)->toBe($reason)
        ->and($refused->position)->toBe($position);
})->with([
    'at the root' => ['{"tasks":[],"note":"x"}', 'unknown_key', ''],
    'no tasks' => ['{}', 'missing_key', ''],
    'in a task' => [aiOutput(aiTask(['tools' => []])), 'unknown_key', 'tasks[0]'],
    'in the second task' => [aiOutput(aiTask(), aiTask(['permissions' => ['system.shell']])), 'unknown_key', 'tasks[1]'],
    'an empty key' => [aiOutput(aiTask(['' => 'x'])), 'unknown_key', 'tasks[0]'],
    'a numeric key' => ['{"tasks":[],"0":"x"}', 'unknown_key', ''],
    'a differently cased key' => [aiOutput(array_diff_key(aiTask(), ['title' => 1]) + ['Title' => 'x']), 'unknown_key', 'tasks[0]'],
]);

it('AI-OUT-01: refuses a task without any of its keys', function (string $key) {
    $task = aiTask();
    unset($task[$key]);

    expect(refusedFor(aiOutput($task))->reason)->toBe('missing_key');
})->with(array_keys(aiTask()));

it('AI-OUT-01: refuses a wrong number of tasks', function (int $count) {
    expect(refusedFor(aiOutput(...array_fill(0, $count, aiTask())))->reason)->toBe('task_count');
})->with([0, 11]);

it('AI-OUT-01: accepts the most it allows', function () {
    expect((new OutputValidator)->validate(aiOutput(...array_fill(0, 10, aiTask()))))->toHaveCount(10);
});

it('AI-OUT-01: refuses a value of the wrong type', function (string $key, mixed $value, string $reason) {
    expect(refusedFor(aiOutput(aiTask([$key => $value])))->reason)->toBe($reason);
})->with([
    ['title', 1, 'not_a_string'],
    ['title', null, 'not_a_string'],
    ['title', ['a'], 'not_a_string'],
    ['description', true, 'not_a_string'],
    ['target_data', 1.5, 'not_a_string'],
    ['impact_summary', null, 'not_a_string'],
    ['steps', 'a', 'not_a_list'],
    ['steps', [1], 'not_a_string'],
    ['requested_permissions', 'a', 'not_a_list'],
    ['requested_permissions', [null], 'not_a_string'],
    ['priority', 1, 'unknown_priority'],
    ['priority', ['low'], 'unknown_priority'],
    ['action_type', 1, 'unknown_action'],
    ['action_type', ['text.analyze'], 'unknown_action'],
    ['action_type', null, 'unknown_action'],
]);

it('AI-OUT-01: takes only the listed priorities', function (string $priority) {
    expect(refusedFor(aiOutput(aiTask(['priority' => $priority])))->reason)->toBe('unknown_priority');
})->with(['critical', 'LOW', ' low', '']);

it('AI-OUT-01: refuses an action that is not listed, exactly as written', function (string $type) {
    $refused = refusedFor(aiOutput(aiTask(['action_type' => $type])));

    expect($refused->reason)->toBe('unknown_action')
        ->and($refused->position)->toBe('tasks[0].action_type');
})->with(['payment.transfer', 'EMAIL.SEND', 'Text.Analyze', ' text.analyze', "text.analyze\n", '', 'ｔｅｘｔ.analyze']);

it('AI-OUT-01: counts characters and stops at each limit', function (string $key, int $limit) {
    $tasks = (new OutputValidator)->validate(aiOutput(aiTask([$key => str_repeat('あ', $limit)])));

    expect($tasks)->toHaveCount(1)
        ->and(refusedFor(aiOutput(aiTask([$key => str_repeat('あ', $limit + 1)])))->reason)->toBe('too_long');
})->with([['title', 100], ['description', 1000], ['target_data', 500], ['impact_summary', 1000]]);

it('AI-OUT-01: limits the steps', function () {
    expect((new OutputValidator)->validate(aiOutput(aiTask(['steps' => array_fill(0, 10, str_repeat('あ', 200))]))))->toHaveCount(1)
        ->and(refusedFor(aiOutput(aiTask(['steps' => []])))->reason)->toBe('item_count')
        ->and(refusedFor(aiOutput(aiTask(['steps' => array_fill(0, 11, 'a')])))->reason)->toBe('item_count')
        ->and(refusedFor(aiOutput(aiTask(['steps' => [str_repeat('あ', 201)]])))->reason)->toBe('too_long');
});

it('AI-OUT-01: limits the requested permissions', function () {
    expect((new OutputValidator)->validate(aiOutput(aiTask(['requested_permissions' => array_fill(0, 20, str_repeat('a', 50))]))))->toHaveCount(1)
        ->and(refusedFor(aiOutput(aiTask(['requested_permissions' => array_fill(0, 21, 'a')])))->reason)->toBe('item_count')
        ->and(refusedFor(aiOutput(aiTask(['requested_permissions' => [str_repeat('a', 51)]])))->reason)->toBe('too_long');
});

it('AI-OUT-01: refuses text with nothing in it', function (string $value) {
    expect(refusedFor(aiOutput(aiTask(['title' => $value])))->reason)->toBe('blank');
})->with(['empty' => '', 'spaces' => '   ', 'a full-width space' => '　', 'line feeds' => "\n\n", 'a zero-width space' => "\u{200B}", 'a no-break space' => "\u{00A0}"]);

it('AI-OUT-01: refuses control characters, except a line feed and a tab', function (string $value) {
    expect(refusedFor(aiOutput(aiTask(['description' => $value])))->reason)->toBe('control_character');
})->with(['NUL' => "a\0b", 'escape' => "a\e[31mb", 'carriage return' => "a\rb", 'delete' => "a\x7Fb", 'C1' => "a\u{0085}b"]);

it('AI-OUT-01: keeps line feeds and tabs, and changes nothing', function () {
    $text = "1行目\n\t2行目 ";

    expect((new OutputValidator)->validate(aiOutput(aiTask(['description' => $text])))[0]->description)->toBe($text);
});

it('AI-OUT-01: refuses more than its size limit before parsing, and the largest valid answer fits', function () {
    $largest = aiOutput(...array_fill(0, 10, aiTask([
        'title' => str_repeat('あ', 100),
        'description' => str_repeat('あ', 1000),
        'steps' => array_fill(0, 10, str_repeat('あ', 200)),
        'requested_permissions' => array_fill(0, 20, str_repeat('あ', 50)),
        'target_data' => str_repeat('あ', 500),
        'impact_summary' => str_repeat('あ', 1000),
    ])));

    expect((new OutputValidator)->validate($largest))->toHaveCount(10)
        ->and(refusedFor(str_repeat(' ', OutputValidator::MAX_BYTES + 1))->reason)->toBe('too_large');
});

it('AI-OUT-01: repeats nothing the AI wrote when it refuses', function (string $output, string $written) {
    $refused = refusedFor($output);

    expect($refused->getMessage())->toStartWith(InvalidAiOutputException::CODE)->not->toContain($written)
        ->and($refused->position)->not->toContain($written);
})->with([
    'an unknown key' => [aiOutput(aiTask(['leaked-key-name' => 'x'])), 'leaked-key-name'],
    'an unknown action' => [aiOutput(aiTask(['action_type' => 'leaked.action'])), 'leaked.action'],
    'broken JSON' => ['{"title": "leaked text', 'leaked text'],
    'too long' => [aiOutput(aiTask(['title' => 'leaked'.str_repeat('x', 100)])), 'leaked'],
]);
