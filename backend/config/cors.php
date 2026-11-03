<?php

/*
| Cross-Origin Resource Sharing (CORS)
|
| SecureFlow AI is operated same-origin only (SPA and API behind the same nginx).
| CORS is therefore disabled: no paths are CORS-enabled and no origins are allowed.
| See docs/security-design.md §15.
*/

return [

    'paths' => [],

    'allowed_methods' => [],

    'allowed_origins' => [],

    'allowed_origins_patterns' => [],

    'allowed_headers' => [],

    'exposed_headers' => [],

    'max_age' => 0,

    'supports_credentials' => false,

];
