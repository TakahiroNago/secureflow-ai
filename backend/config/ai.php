<?php

return [

    // Only "mock" exists until step 2-8. docs/architecture.md §11, docs/security-design.md §6.1.
    'provider' => env('AI_PROVIDER', 'mock'),

    'timeout_seconds' => (int) env('AI_TIMEOUT_SECONDS', 30),

    'max_output_tokens' => (int) env('AI_MAX_OUTPUT_TOKENS', 2000),

];
