<?php

/*
| Audit log settings (docs/security-design.md §16.5, docs/architecture.md §11).
| Every number here is a provisional value, not a measured one: see AUDIT-LOAD-01.
*/
return [
    'login_ip_limit_per_minute' => (int) env('AUDIT_LOGIN_IP_LIMIT_PER_MINUTE', 30),
    'system_chain_limit_per_minute' => (int) env('AUDIT_SYSTEM_CHAIN_LIMIT_PER_MINUTE', 600),

    'db_unavailable_ttl_seconds' => (int) env('DB_UNAVAILABLE_TTL_SECONDS', 30),
    'recheck_interval_seconds' => (int) env('AUDIT_RECHECK_INTERVAL_SECONDS', 30),
    'probe_min_interval_seconds' => (int) env('AUDIT_PROBE_MIN_INTERVAL_SECONDS', 5),
    'preflight_timeout_ms' => (int) env('AUDIT_PREFLIGHT_TIMEOUT_MS', 1000),

    'log_aggregation_interval_seconds' => (int) env('LOG_AGGREGATION_INTERVAL_SECONDS', 60),
    // A path under sys_get_temp_dir() unless set. Never shared between containers.
    'log_state_directory' => env('AUDIT_LOG_STATE_DIRECTORY'),

    'password_change_replay_minutes' => (int) env('PASSWORD_CHANGE_REPLAY_MINUTES', 15),
    'password_pending_redis_timeout_ms' => (int) env('PASSWORD_PENDING_REDIS_TIMEOUT_MS', 1000),
    'password_pending_ttl_margin_seconds' => (int) env('PASSWORD_PENDING_TTL_MARGIN_SECONDS', 300),
];
