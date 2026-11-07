<?php

use App\Ai\AiConfiguration;
use App\Ai\AiFailure;
use App\Ai\AiGateway;
use App\Ai\AiOutputSchema;
use App\Ai\AiPricing;
use App\Ai\AiProviderException;
use App\Ai\AiRequest;
use App\Ai\AiResponse;
use App\Ai\AiTokens;
use App\Ai\PromptBuilder;
use App\Ai\Providers\OpenAiProvider;
use App\Security\Policy\ActionCatalog;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;

/*
| ST-31 and everything OpenAI can answer, with a fake HTTP client. No call reaches OpenAI here, and no key exists. What
| the real API does with this is only checked by the manual call of step 2-8 (docs/test-strategy.md §28).
*/

const FAKE_KEY = 'test-key-not-a-real-one';

const OPENAI_URL = 'https://api.openai.com/v1/responses';

function openAi(): OpenAiProvider
{
    return new OpenAiProvider(FAKE_KEY, 'gpt-6-luna');
}

function askOpenAi(?OpenAiProvider $provider = null): AiResponse
{
    return ($provider ?? openAi())->generate(new AiRequest('固定のシステムプロンプト', 'マスク済みの入力', 2000, 30));
}

function answered(array $overrides = []): array
{
    return [
        'id' => 'resp_1',
        'status' => 'completed',
        'output' => [
            ['type' => 'reasoning', 'summary' => []],
            ['type' => 'message', 'content' => [['type' => 'output_text', 'text' => '{"tasks":[]}']]],
        ],
        'usage' => ['input_tokens' => 120, 'output_tokens' => 80, 'total_tokens' => 200],
        ...$overrides,
    ];
}

function failureOf(Closure $call): AiProviderException
{
    try {
        $call();
    } catch (AiProviderException $exception) {
        return $exception;
    }

    throw new RuntimeException('It did not fail.');
}

beforeEach(function () {
    Http::preventStrayRequests();
    Sleep::fake();
});

// ---- ST-31: what is sent, and where ---------------------------------------------------------------

it('ST-31: sends exactly what was reviewed, to the fixed address, and nothing about who is asking', function () {
    Http::fake([OPENAI_URL => Http::response(answered())]);

    askOpenAi();

    Http::assertSent(function (Request $request) {
        expect($request->url())->toBe(OPENAI_URL)
            ->and($request->method())->toBe('POST')
            ->and($request->header('Authorization'))->toBe(['Bearer '.FAKE_KEY])
            ->and(array_keys($request->data()))->toEqualCanonicalizing(['model', 'instructions', 'input', 'text', 'max_output_tokens', 'store'])
            ->and($request['model'])->toBe('gpt-6-luna')
            ->and($request['instructions'])->toBe('固定のシステムプロンプト')
            ->and($request['input'])->toBe('マスク済みの入力')
            ->and($request['max_output_tokens'])->toBe(2000)
            ->and($request['store'])->toBeFalse()
            ->and($request->data())->not->toHaveKeys(['tools', 'tool_choice', 'user', 'safety_identifier', 'metadata', 'prompt_cache_key'])
            ->and($request['text']['format']['type'])->toBe('json_schema')
            ->and($request['text']['format']['strict'])->toBeTrue();

        return true;
    });
});

it('ST-31: the address does not come from the environment', function () {
    config(['ai.openai.base_url' => 'https://somewhere.example/v1']);
    Http::fake([OPENAI_URL => Http::response(answered())]);

    askOpenAi();

    Http::assertSentCount(1);
    Http::assertSent(fn (Request $request) => $request->url() === OPENAI_URL);
});

it('sends a schema that strict mode can take, with every action so that a forbidden one is reported', function () {
    $schema = AiOutputSchema::definition();
    $task = $schema['properties']['tasks']['items'];

    expect($schema['additionalProperties'])->toBeFalse()
        ->and($schema['required'])->toBe(['tasks'])
        ->and($task['additionalProperties'])->toBeFalse()
        ->and($task['required'])->toEqualCanonicalizing(array_keys($task['properties']))
        ->and($task['properties']['action_type']['enum'])->toBe(ActionCatalog::types())
        ->and(json_encode($schema))->not->toContain('minLength')
        ->and(json_encode($schema))->not->toContain('maxLength');
});

// ---- Answers ---------------------------------------------------------------------------------------

it('takes the text, what it used and the id, past items that are not the message', function () {
    Http::fake([OPENAI_URL => Http::response(answered(), 200, ['x-request-id' => 'req_abc'])]);

    $response = askOpenAi();

    expect($response->content)->toBe('{"tasks":[]}')
        ->and($response->model)->toBe('gpt-6-luna')
        ->and($response->requestId)->toBe('req_abc')
        ->and($response->tokens)->toEqual(new AiTokens(120, 80, 200));
});

it('joins the parts of the text', function () {
    Http::fake([OPENAI_URL => Http::response(answered(['output' => [['type' => 'message', 'content' => [
        ['type' => 'output_text', 'text' => '{"tas'],
        ['type' => 'output_text', 'text' => 'ks":[]}'],
    ]]]]))]);

    expect(askOpenAi()->content)->toBe('{"tasks":[]}');
});

it('has no tokens when none were reported, rather than zero', function () {
    Http::fake([OPENAI_URL => Http::response(answered(['usage' => null]))]);

    expect(askOpenAi()->tokens)->toBeNull();
});

it('says a refusal is one, and keeps what it used', function () {
    Http::fake([OPENAI_URL => Http::response(answered(['output' => [['type' => 'message', 'content' => [['type' => 'refusal', 'refusal' => 'できません']]]]]))]);

    $failure = failureOf(fn () => askOpenAi());

    expect($failure->failure)->toBe(AiFailure::Refused)
        ->and($failure->tokens)->toEqual(new AiTokens(120, 80, 200))
        ->and($failure->getMessage())->not->toContain('できません');
});

it('does not take a cut-off answer, and keeps what it used', function () {
    Http::fake([OPENAI_URL => Http::response(answered(['status' => 'incomplete', 'incomplete_details' => ['reason' => 'max_output_tokens']]))]);

    $failure = failureOf(fn () => askOpenAi());

    expect($failure->failure)->toBe(AiFailure::Incomplete)->and($failure->tokens?->total)->toBe(200);
});

it('does not take an answer of the wrong shape', function (array $body) {
    Http::fake([OPENAI_URL => Http::response($body)]);

    expect(failureOf(fn () => askOpenAi())->failure)->toBe(AiFailure::Malformed);
})->with([
    'a failed status' => [answered(['status' => 'failed'])],
    'no status' => [['output' => answered()['output']]],
    'no output' => [answered(['output' => []])],
    'empty text' => [answered(['output' => [['type' => 'message', 'content' => [['type' => 'output_text', 'text' => '']]]]])],
    'not a list' => [answered(['output' => 'text'])],
    'text of another type' => [answered(['output' => [['type' => 'message', 'content' => [['type' => 'output_text', 'text' => 7]]]]])],
    'content items of no use' => [answered(['output' => [['type' => 'message', 'content' => ['text', 7]]]])],
]);

// ---- Errors ----------------------------------------------------------------------------------------

it('tells the failures apart, by status and code', function (int $status, array $error, AiFailure $expected, bool $retried) {
    Http::fake([OPENAI_URL => Http::response(['error' => $error], $status)]);

    $failure = failureOf(fn () => askOpenAi());

    expect($failure->failure)->toBe($expected)
        ->and($failure->failure->isRetryable())->toBe($retried);
})->with([
    'a bad key' => [401, ['code' => 'invalid_api_key'], AiFailure::Unauthorized, false],
    'an unsupported country' => [403, ['code' => 'unsupported_country_region_territory'], AiFailure::Unauthorized, false],
    'a bad request' => [400, ['code' => 'invalid_json_schema'], AiFailure::Rejected, false],
    'a redirect is not followed' => [302, [], AiFailure::Rejected, false],
    'pacing' => [429, ['code' => 'rate_limit_exceeded'], AiFailure::RateLimited, true],
    'slowing down' => [429, ['code' => 'slow_down', 'type' => 'rate_limit_error'], AiFailure::RateLimited, true],
    'no credit' => [429, ['code' => 'credit_balance_exhausted', 'type' => 'insufficient_quota'], AiFailure::QuotaExceeded, false],
    'quota by type' => [429, ['type' => 'insufficient_quota'], AiFailure::QuotaExceeded, false],
    'project spend limit' => [429, ['code' => 'project_spend_limit_exceeded'], AiFailure::QuotaExceeded, false],
    'organization spend limit' => [429, ['code' => 'organization_spend_limit_exceeded'], AiFailure::QuotaExceeded, false],
    'approved limit' => [429, ['code' => 'organization_usage_limit_exceeded'], AiFailure::QuotaExceeded, false],
    'a server error' => [500, [], AiFailure::ServerError, true],
    'overloaded' => [503, ['code' => 'server_is_overloaded'], AiFailure::ServerError, true],
]);

it('treats a connection that fails as a timeout, including a certificate that does not verify', function () {
    Http::fake(fn () => throw new ConnectionException('SSL certificate problem: unable to get local issuer certificate'));

    $failure = failureOf(fn () => askOpenAi());

    expect($failure->failure)->toBe(AiFailure::Timeout)
        ->and($failure->getMessage())->not->toContain('certificate');
});

it('reads Retry-After when it is a number', function (string $value, ?int $expected) {
    Http::fake([OPENAI_URL => Http::response([], 429, ['Retry-After' => $value])]);

    expect(failureOf(fn () => askOpenAi())->retryAfterSeconds)->toBe($expected);
})->with([['3', 3], ['soon', null], ['', null]]);

it('puts nothing of the request, the answer or the key in a log', function () {
    $logged = [];
    Event::listen(MessageLogged::class, function (MessageLogged $message) use (&$logged): void {
        $logged[] = $message->message.json_encode($message->context);
    });
    Http::fake([OPENAI_URL => Http::response(['error' => ['code' => 'invalid_api_key', 'message' => 'Incorrect API key provided: '.FAKE_KEY]], 401)]);

    $failure = failureOf(fn () => askOpenAi());

    expect($logged)->not->toBe([])
        ->and(implode("\n", $logged))->not->toContain(FAKE_KEY)
        ->and(implode("\n", $logged))->not->toContain('マスク済みの入力')
        ->and($failure->getMessage())->not->toContain(FAKE_KEY);
});

// ---- With the gateway ------------------------------------------------------------------------------

it('tries again only for what can pass, and waits what it is told, up to a limit', function () {
    Http::fake([OPENAI_URL => Http::sequence()
        ->push([], 429, ['Retry-After' => '4'])
        ->push([], 503, ['Retry-After' => '999'])
        ->push(answered())]);

    $response = (new AiGateway(openAi(), 30, 2000))->generate('system', 'input');

    expect($response->content)->toBe('{"tasks":[]}');
    Http::assertSentCount(3);
    Sleep::assertSequence([Sleep::for(4)->seconds(), Sleep::for(5)->seconds()]);
});

it('does not try again for what cannot pass', function (int $status, array $error) {
    Http::fake([OPENAI_URL => Http::response(['error' => $error], $status)]);

    failureOf(fn () => (new AiGateway(openAi(), 30, 2000))->generate('system', 'input'));

    Http::assertSentCount(1);
})->with([
    [401, []],
    [400, []],
    [429, ['code' => 'credit_balance_exhausted']],
]);

it('does not try again for a refusal or a cut-off answer', function (array $body) {
    Http::fake([OPENAI_URL => Http::response($body)]);

    failureOf(fn () => (new AiGateway(openAi(), 30, 2000))->generate('system', 'input'));

    Http::assertSentCount(1);
})->with([
    [answered(['status' => 'incomplete'])],
    [answered(['output' => [['type' => 'message', 'content' => [['type' => 'refusal', 'refusal' => 'x']]]]])],
]);

it('sends the prompt of PromptBuilder, with the input only inside its boundary', function () {
    Http::fake([OPENAI_URL => Http::response(answered())]);
    $prompt = app(PromptBuilder::class)->build('週次の報告');

    (new AiGateway(openAi(), 30, 2000))->generate($prompt->systemPrompt, $prompt->input);

    Http::assertSent(fn (Request $request) => ! str_contains((string) $request['instructions'], '週次の報告') && str_contains((string) $request['input'], '週次の報告'));
});

// ---- Cost ------------------------------------------------------------------------------------------

it('estimates the cost from the prices that were read', function () {
    expect(AiPricing::estimateMicros('gpt-6-luna', new AiTokens(3000, 2000, 5000)))->toBe(1300)
        ->and(AiPricing::estimateMicros('other', new AiTokens(1, 1, 2)))->toBeNull();
});

it('uses only the address that was reviewed', function () {
    expect(AiConfiguration::OPENAI_BASE_URL)->toBe('https://api.openai.com/v1');
});
