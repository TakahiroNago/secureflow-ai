<?php

use App\Ai\AiConfiguration;
use App\Ai\AiGateway;
use App\Ai\AiRequest;
use App\Ai\Contracts\AiProvider;
use App\Ai\Providers\MockAiProvider;
use App\Ai\Providers\MockScenario;
use Illuminate\Contracts\Process\ProcessResult;
use Illuminate\Support\Facades\Process;

/*
| AI-CONF-01. docs/architecture.md §11: which provider may run where, and that the application refuses to
| start otherwise. Separate processes, because the check runs while Laravel boots.
*/

function aiArtisan(array $environment, string ...$arguments): ProcessResult
{
    return Process::path(base_path())->env([...$environment, 'CACHE_STORE' => 'array', 'QUEUE_CONNECTION' => 'sync'])->run(['php', 'artisan', ...$arguments]);
}

/** Boots as php-fpm does. Laravel asks this variable whether it runs in a console. */
function aiWebBoot(array $environment): ProcessResult
{
    return Process::path(base_path())->env([...$environment, 'APP_RUNNING_IN_CONSOLE' => 'false', 'CACHE_STORE' => 'array'])->run([
        'php', '-r', 'require "vendor/autoload.php"; $app = require "bootstrap/app.php"; $app->make(Illuminate\Contracts\Http\Kernel::class)->bootstrap(); echo "started";',
    ]);
}

$bad = [
    'the real provider, before step 2-8' => [['APP_ENV' => 'local', 'AI_PROVIDER' => 'openai']],
    'an unknown value' => [['APP_ENV' => 'local', 'AI_PROVIDER' => 'other']],
    'an empty value' => [['APP_ENV' => 'local', 'AI_PROVIDER' => '']],
    'a differently cased value' => [['APP_ENV' => 'local', 'AI_PROVIDER' => 'Mock']],
    'the mock in production' => [['APP_ENV' => 'production', 'AI_PROVIDER' => 'mock']],
    'the mock in staging' => [['APP_ENV' => 'staging', 'AI_PROVIDER' => 'mock']],
    'the real provider in production' => [['APP_ENV' => 'production', 'AI_PROVIDER' => 'openai']],
];

it('AI-CONF-01: the web application refuses to start', function (array $environment) {
    $result = aiWebBoot($environment);

    expect($result->successful())->toBeFalse()
        ->and($result->output())->not->toContain('started');
})->with($bad);

it('AI-CONF-01: the worker and the scheduler refuse to start', function (string $command, array $environment) {
    $result = aiArtisan($environment, ...explode(' ', $command));

    expect($result->successful())->toBeFalse()
        ->and($result->output().$result->errorOutput())->toContain('AI_PROVIDER');
})->with(['queue:work sync --stop-when-empty', 'schedule:run'])->with($bad);

it('AI-CONF-01: the web application starts with the mock in development and tests', function (string $environment) {
    $result = aiWebBoot(['APP_ENV' => $environment, 'AI_PROVIDER' => 'mock']);

    expect($result->output())->toContain('started');
})->with(['local', 'testing']);

it('AI-CONF-01: the worker starts with the mock in development', function () {
    $result = aiArtisan(['APP_ENV' => 'local', 'AI_PROVIDER' => 'mock'], 'queue:work', 'sync', '--stop-when-empty');

    expect($result->output().$result->errorOutput())->not->toContain('AI_PROVIDER')
        ->and($result->successful())->toBeTrue();
});

it('AI-CONF-01: a maintenance command still runs, so that an incident can be handled', function () {
    $result = aiArtisan(['APP_ENV' => 'production', 'AI_PROVIDER' => 'mock'], '--version');

    expect($result->successful())->toBeTrue();
});

it('AI-CONF-01: reaching a provider checks again, for whatever skipped the start', function (string $provider, string $environment) {
    config(['ai.provider' => $provider]);
    app()['env'] = $environment;

    expect(fn () => app(AiProvider::class))->toThrow(RuntimeException::class)
        ->and(fn () => app(AiGateway::class))->toThrow(RuntimeException::class);
})->with([['openai', 'local'], ['other', 'local'], ['mock', 'production'], ['mock', 'unknown']]);

it('AI-CONF-01: a message does not repeat the configured value, which could be a misplaced secret', function () {
    expect(fn () => AiConfiguration::assertValid('sk-a-misplaced-secret', 'local'))
        ->toThrow(fn (RuntimeException $exception) => expect($exception->getMessage())->not->toContain('sk-a-misplaced-secret'));
});

it('AI-CONF-01: the application gets the mock with its normal answers, and the settings', function () {
    config(['ai.provider' => 'mock', 'ai.timeout_seconds' => 7]);

    expect(app(AiProvider::class))->toBeInstanceOf(MockAiProvider::class)
        ->and(app(AiGateway::class)->generate('s', 'i')->content)->toBe((new MockAiProvider(MockScenario::Normal))->generate(new AiRequest('s', 'i', 1, 1))->content)
        ->and(app(AiGateway::class)->worstCaseSeconds())->toBe(24);
});
