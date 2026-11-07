<?php

namespace App\Ai\Providers;

use App\Ai\AiConfiguration;
use App\Ai\AiFailure;
use App\Ai\AiOutputSchema;
use App\Ai\AiProviderException;
use App\Ai\AiRequest;
use App\Ai\AiResponse;
use App\Ai\AiTokens;
use App\Ai\Contracts\AiProvider;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use SensitiveParameter;

/**
 * The Responses API (docs/security-design.md §6, §6.1). The request holds the model, the fixed instructions, the masked
 * input, the schema, the limit and store: false, and nothing else: no tools, and nothing about who is asking. The
 * address is a constant. An answer is untrusted, so what comes back goes through OutputScanner like the mock's.
 *
 * No request text, response text or key reaches a log or an exception from here.
 */
final readonly class OpenAiProvider implements AiProvider
{
    private const ENDPOINT = '/responses';

    private const CONNECT_TIMEOUT_SECONDS = 5;

    private const SCHEMA_NAME = 'workflow_plan';

    /** Trying again does not help these. docs: "Retrying billing, spend, or quota errors won't restore API access." */
    private const QUOTA_CODES = ['insufficient_quota', 'credit_balance_exhausted', 'organization_spend_limit_exceeded', 'project_spend_limit_exceeded', 'organization_usage_limit_exceeded'];

    public function __construct(
        #[SensitiveParameter]
        private string $apiKey,
        private string $model,
    ) {}

    public function generate(AiRequest $request): AiResponse
    {
        try {
            $response = Http::baseUrl(AiConfiguration::OPENAI_BASE_URL)
                ->withToken($this->apiKey)
                ->acceptJson()
                ->asJson()
                ->withoutRedirecting()
                ->connectTimeout(self::CONNECT_TIMEOUT_SECONDS)
                ->timeout($request->timeoutSeconds)
                ->post(self::ENDPOINT, $this->payload($request));
        } catch (ConnectionException) {
            // Its message is not kept. This also covers a certificate that fails verification.
            Log::warning('ai.connection_failed', ['metric' => 'ai.connection_failed']);

            throw new AiProviderException(AiFailure::Timeout);
        }

        if (! $response->successful()) {
            throw $this->failureOf($response);
        }

        return $this->answerOf($response);
    }

    /**
     * @return array<string, mixed>
     */
    private function payload(AiRequest $request): array
    {
        return [
            'model' => $this->model,
            'instructions' => $request->systemPrompt,
            'input' => $request->input,
            'text' => ['format' => [
                'type' => 'json_schema',
                'name' => self::SCHEMA_NAME,
                'strict' => true,
                'schema' => AiOutputSchema::definition(),
            ]],
            'max_output_tokens' => $request->maxOutputTokens,
            'store' => false,
        ];
    }

    private function answerOf(Response $response): AiResponse
    {
        $tokens = $this->tokensOf($response);
        $status = $response->json('status');

        if ($status === 'incomplete') {
            throw new AiProviderException(AiFailure::Incomplete, tokens: $tokens);
        }

        $text = '';

        foreach ((array) $response->json('output') as $item) {
            foreach (is_array($item) && is_array($item['content'] ?? null) ? $item['content'] : [] as $content) {
                if (! is_array($content)) {
                    continue;
                }

                if (($content['type'] ?? null) === 'refusal') {
                    throw new AiProviderException(AiFailure::Refused, tokens: $tokens);
                }

                if (($content['type'] ?? null) === 'output_text' && is_string($content['text'] ?? null)) {
                    $text .= $content['text'];
                }
            }
        }

        if ($status !== 'completed' || $text === '') {
            throw new AiProviderException(AiFailure::Malformed, tokens: $tokens);
        }

        return new AiResponse($text, $tokens, $this->model, $this->requestIdOf($response));
    }

    private function tokensOf(Response $response): ?AiTokens
    {
        $input = $response->json('usage.input_tokens');
        $output = $response->json('usage.output_tokens');
        $total = $response->json('usage.total_tokens');

        return is_int($input) && is_int($output) && is_int($total) ? new AiTokens($input, $output, $total) : null;
    }

    private function requestIdOf(Response $response): ?string
    {
        $id = $response->header('x-request-id');

        return $id === '' ? null : mb_substr($id, 0, 128);
    }

    /**
     * By status and the fixed code only. The rest of an error's body is never read.
     */
    private function failureOf(Response $response): AiProviderException
    {
        $status = $response->status();
        $code = $response->json('error.code');
        $type = $response->json('error.type');

        $failure = match (true) {
            $status === 401, $status === 403 => AiFailure::Unauthorized,
            $status === 429 && (in_array($code, self::QUOTA_CODES, true) || in_array($type, self::QUOTA_CODES, true)) => AiFailure::QuotaExceeded,
            $status === 429 => AiFailure::RateLimited,
            $status >= 500 => AiFailure::ServerError,
            default => AiFailure::Rejected,
        };

        if (! $failure->isRetryable()) {
            // Someone has to do something: the key, the access, the balance or the request itself.
            Log::error('ai.provider_refused', ['metric' => 'ai.provider_refused', 'failure' => $failure->value, 'status' => $status]);
        }

        return new AiProviderException($failure, $this->retryAfterOf($response));
    }

    private function retryAfterOf(Response $response): ?int
    {
        $value = $response->header('Retry-After');

        return ctype_digit($value) ? (int) $value : null;
    }
}
