<?php

namespace App\Ai\Contracts;

use App\Ai\AiProviderException;
use App\Ai\AiRequest;
use App\Ai\AiResponse;

interface AiProvider
{
    /**
     * @throws AiProviderException
     */
    public function generate(AiRequest $request): AiResponse;
}
