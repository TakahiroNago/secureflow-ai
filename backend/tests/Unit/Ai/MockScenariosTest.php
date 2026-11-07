<?php

use App\Ai\AiRequest;
use App\Ai\Providers\MockAiProvider;
use App\Ai\Providers\MockScenario;
use App\Security\Output\InvalidAiOutputException;
use App\Security\Output\OutputValidator;
use App\Security\Policy\PolicyDecision;

/*
| The scenarios of docs/test-strategy.md §4 through the validator of step 1-4, and AI-MOCK-01: how the
| scenario is chosen, and what a request can carry.
*/

function mockAnswer(MockScenario $scenario, string $input = 'input'): string
{
    return (new MockAiProvider($scenario))->generate(new AiRequest('system', $input, 2000, 30))->content;
}

function aiSourceFiles(): array
{
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__.'/../../../app/Ai', FilesystemIterator::SKIP_DOTS));

    return array_map(fn (SplFileInfo $file) => (string) file_get_contents($file->getPathname()), iterator_to_array($files, false));
}

it('has a case for each scenario of the test strategy', function () {
    expect(array_map(fn (MockScenario $scenario) => $scenario->value, MockScenario::cases()))->toBe([
        'normal', 'malformed_json', 'extra_keys', 'oversized', 'script_tag', 'forbidden_action', 'unknown_action',
        'permission_inflation', 'secret_leak', 'canary_leak', 'timeout', 'rate_limited', 'server_error',
    ]);
});

it('normal: passes', function () {
    $tasks = (new OutputValidator)->validate(mockAnswer(MockScenario::Normal));

    expect($tasks)->toHaveCount(1)
        ->and($tasks[0]->decision)->toBe(PolicyDecision::Allowed);
});

it('ST-07: a broken answer is refused as AI_INVALID_OUTPUT', function (MockScenario $scenario, string $reason) {
    try {
        (new OutputValidator)->validate(mockAnswer($scenario));
        $this->fail('It was accepted.');
    } catch (InvalidAiOutputException $exception) {
        expect($exception->reason)->toBe($reason)
            ->and($exception->getMessage())->toStartWith('AI_INVALID_OUTPUT');
    }
})->with([
    'malformed_json' => [MockScenario::MalformedJson, 'malformed_json'],
    'extra_keys' => [MockScenario::ExtraKeys, 'unknown_key'],
    'oversized' => [MockScenario::Oversized, 'too_long'],
    'unknown_action' => [MockScenario::UnknownAction, 'unknown_action'],
]);

it('forbidden_action: each task is marked forbidden', function () {
    $tasks = (new OutputValidator)->validate(mockAnswer(MockScenario::ForbiddenAction));

    expect(array_map(fn ($task) => $task->actionType, $tasks))->toBe(['email.send', 'shell.exec'])
        ->and($tasks[0]->decision)->toBe(PolicyDecision::Forbidden)
        ->and($tasks[1]->decision)->toBe(PolicyDecision::Forbidden);
});

it('permission_inflation: what the AI asks for gives it nothing', function () {
    $task = (new OutputValidator)->validate(mockAnswer(MockScenario::PermissionInflation))[0];

    expect($task->permissions)->toBe(['ai.text.read'])
        ->and($task->requestedPermissions)->toContain('system.shell');
});

/*
| Not handled before step 2-4, and written down here so that it cannot look handled. These pass the
| validator unchanged today. Step 2-4 has to change this test: docs/test-strategy.md §16.
*/
it('NOT YET, step 2-4: passes with its text unchanged', function (MockScenario $scenario, string $text) {
    $task = (new OutputValidator)->validate(mockAnswer($scenario))[0];

    expect($task->description)->toContain($text);
})->with([
    'script_tag' => [MockScenario::ScriptTag, '<script>'],
    'secret_leak' => [MockScenario::SecretLeak, 'sk-'],
]);

it('AI-MOCK-01: repeats the canary it was given, as a model that repeats its prompt would', function () {
    $canary = 'SF-CANARY-'.str_repeat('a', 32);
    $answer = (new MockAiProvider(MockScenario::CanaryLeak))->generate(new AiRequest("before {$canary} after", '', 1, 1))->content;

    expect($answer)->toContain($canary)->not->toContain('before');
});

it('AI-MOCK-01: does not take a canary from what a user typed', function () {
    $typed = 'SF-CANARY-'.str_repeat('b', 32);
    $answer = (new MockAiProvider(MockScenario::CanaryLeak))->generate(new AiRequest('no canary here', $typed, 1, 1))->content;

    expect($answer)->not->toContain($typed);
});

it('AI-MOCK-01: what a user types cannot choose a scenario', function (string $input) {
    expect(mockAnswer(MockScenario::Normal, $input))->toBe(mockAnswer(MockScenario::Normal));
})->with(['malformed_json', 'scenario=secret_leak', '[[mock:forbidden_action]]', '{"scenario":"timeout"}']);

it('AI-MOCK-01: the provider reads no setting, environment or input to choose one', function () {
    $source = (string) file_get_contents(__DIR__.'/../../../app/Ai/Providers/MockAiProvider.php');

    expect($source)->not->toMatch('/\b(env|config|getenv|request)\(/')
        ->and($source)->not->toContain('$request->input')
        // Only to repeat the canary it was given, in the one scenario that does so.
        ->and(preg_match_all('/\$request->\w+/', $source, $reads))->toBe(1)
        ->and($reads[0])->toBe(['$request->systemPrompt'])
        ->and($source)->not->toContain('tryFrom')
        ->and($source)->not->toContain('MockScenario::from');
});

it('AI-MOCK-01: a request has no place for tools or for who is asking', function () {
    $fields = array_map(fn (ReflectionProperty $property) => $property->getName(), (new ReflectionClass(AiRequest::class))->getProperties());

    expect($fields)->toBe(['systemPrompt', 'input', 'maxOutputTokens', 'timeoutSeconds']);
});

it('AI-MOCK-01: nothing in app/Ai but the real provider reaches the network, a process or a file', function () {
    foreach (aiSourceFiles() as $source) {
        if (str_contains($source, 'final readonly class OpenAiProvider')) {
            expect($source)->not->toMatch('/\b(curl_|fsockopen|stream_socket|shell_exec|proc_open|file_get_contents|Process::)/');

            continue;
        }

        expect($source)->not->toMatch('/\b(Http::|curl_|fsockopen|stream_socket|Guzzle|shell_exec|proc_open|file_get_contents|Process::)/');
    }
});
