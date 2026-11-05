<?php

use App\Ai\AiGateway;
use App\Ai\AiRequest;
use App\Ai\AiResponse;
use App\Ai\Contracts\AiProvider;
use App\Ai\Providers\MockAiProvider;
use App\Ai\Providers\MockScenario;
use App\Security\Output\InvalidAiOutputException;
use App\Security\Output\OutputValidator;

/*
| ST-07, AI output half (docs/test-strategy.md §5): from the gateway to the validator, as the application
| wires them. The request half, 422, comes with the API in step 1-6.
*/

it('ST-07: invalid JSON from the AI is refused once, without another call', function () {
    $provider = new class implements AiProvider
    {
        public int $calls = 0;

        public function generate(AiRequest $request): AiResponse
        {
            $this->calls++;

            return (new MockAiProvider(MockScenario::MalformedJson))->generate($request);
        }
    };
    app()->instance(AiProvider::class, $provider);

    expect(fn () => app(OutputValidator::class)->validate(app(AiGateway::class)->generate('s', 'i')->content))
        ->toThrow(InvalidAiOutputException::class)
        ->and($provider->calls)->toBe(1);
});
