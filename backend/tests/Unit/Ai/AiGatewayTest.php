<?php

use App\Ai\AiFailure;
use App\Ai\AiGateway;
use App\Ai\AiProviderException;
use App\Ai\AiRequest;
use App\Ai\AiResponse;
use App\Ai\Contracts\AiProvider;
use App\Ai\Providers\MockAiProvider;
use App\Ai\Providers\MockScenario;
use Illuminate\Support\Sleep;

/*
| AI-GW-01. docs/security-design.md §6: retries, their backoff and what a provider is given.
*/

/** Fails with each of these in turn, then answers. */
function scriptedProvider(AiFailure ...$failures): AiProvider
{
    return new class($failures) implements AiProvider
    {
        public int $calls = 0;

        public ?AiRequest $request = null;

        /** @param list<AiFailure> $failures */
        public function __construct(private array $failures) {}

        public function generate(AiRequest $request): AiResponse
        {
            $this->calls++;
            $this->request = $request;
            $failure = array_shift($this->failures);

            return $failure === null ? new AiResponse('answer') : throw new AiProviderException($failure);
        }
    };
}

beforeEach(fn () => Sleep::fake());
afterEach(fn () => Sleep::fake(false));

it('AI-GW-01: returns the answer, without waiting, when the first attempt works', function () {
    $provider = scriptedProvider();

    expect((new AiGateway($provider, 30, 2000))->generate('system', 'input')->content)->toBe('answer')
        ->and($provider->calls)->toBe(1);

    Sleep::assertNeverSlept();
});

it('AI-GW-01: gives the provider the limits, the prompt and the input', function () {
    $provider = scriptedProvider();

    (new AiGateway($provider, 12, 345))->generate('system', 'input');

    expect($provider->request)->toEqual(new AiRequest('system', 'input', 345, 12));
});

it('AI-GW-01: retries what can pass, with a growing wait, then answers', function (AiFailure $failure) {
    $provider = scriptedProvider($failure, $failure);

    expect((new AiGateway($provider, 30, 2000))->generate('s', 'i')->content)->toBe('answer')
        ->and($provider->calls)->toBe(3);

    Sleep::assertSequence([Sleep::for(1)->seconds(), Sleep::for(2)->seconds()]);
})->with([AiFailure::Timeout, AiFailure::RateLimited, AiFailure::ServerError]);

it('AI-GW-01: stops after 3 attempts with the last failure', function (MockScenario $scenario, AiFailure $failure) {
    $gateway = new AiGateway(new MockAiProvider($scenario), 30, 2000);

    try {
        $gateway->generate('s', 'i');
        $this->fail('It did not throw.');
    } catch (AiProviderException $exception) {
        expect($exception->failure)->toBe($failure);
    }

    Sleep::assertSleptTimes(2);
})->with([
    [MockScenario::Timeout, AiFailure::Timeout],
    [MockScenario::RateLimited, AiFailure::RateLimited],
    [MockScenario::ServerError, AiFailure::ServerError],
]);

it('AI-GW-01: does not retry a rejected request', function () {
    $provider = scriptedProvider(AiFailure::Rejected);

    expect(fn () => (new AiGateway($provider, 30, 2000))->generate('s', 'i'))->toThrow(AiProviderException::class)
        ->and($provider->calls)->toBe(1);

    Sleep::assertNeverSlept();
});

it('AI-GW-01: does not retry an answer that is invalid, because it does not read answers', function () {
    $provider = new MockAiProvider(MockScenario::MalformedJson);

    expect((new AiGateway($provider, 30, 2000))->generate('s', 'i')->content)->toContain('途中で切れた');

    Sleep::assertNeverSlept();
});

it('AI-GW-01: knows how long one call can take, for the time limit of the job in step 1-6', function () {
    expect((new AiGateway(scriptedProvider(), 30, 2000))->worstCaseSeconds())->toBe(100)
        ->and((new AiGateway(scriptedProvider(), 10, 2000))->worstCaseSeconds())->toBe(40);
});

it('AI-GW-01: says nothing about the request or the answer in a failure', function () {
    $exception = new AiProviderException(AiFailure::ServerError);

    expect($exception->getMessage())->toBe('The AI provider failed: server_error');
});
