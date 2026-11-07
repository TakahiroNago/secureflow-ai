<?php

return [

    // "mock" or "openai". docs/architecture.md §11, docs/security-design.md §6.1.
    'provider' => env('AI_PROVIDER', 'mock'),

    'timeout_seconds' => (int) env('AI_TIMEOUT_SECONDS', 30),

    'max_output_tokens' => (int) env('AI_MAX_OUTPUT_TOKENS', 2000),

    'openai' => [
        'api_key' => (string) env('OPENAI_API_KEY', ''),
        'model' => (string) env('OPENAI_MODEL', ''),
        // Checked against the one reviewed address when the provider starts. Requests never use this value.
        'base_url' => (string) env('OPENAI_BASE_URL', 'https://api.openai.com/v1'),
    ],

];
