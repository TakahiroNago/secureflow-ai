<?php

namespace Tests\Support;

use App\Ai\AiRequest;
use App\Ai\AiResponse;
use App\Ai\Contracts\AiProvider;
use App\Ai\Providers\MockAiProvider;

/**
 * Counts the calls and keeps what was sent, so that a test can say the AI was not called, or never saw a text.
 */
final class RecordingAiProvider implements AiProvider
{
    /** @var list<AiRequest> */
    public array $requests = [];

    public function __construct(private readonly AiProvider $inner = new MockAiProvider) {}

    public function generate(AiRequest $request): AiResponse
    {
        $this->requests[] = $request;

        return $this->inner->generate($request);
    }
}
