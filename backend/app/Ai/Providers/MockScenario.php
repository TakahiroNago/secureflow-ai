<?php

namespace App\Ai\Providers;

/**
 * docs/test-strategy.md §4.
 */
enum MockScenario: string
{
    case Normal = 'normal';
    case MalformedJson = 'malformed_json';
    case ExtraKeys = 'extra_keys';
    case Oversized = 'oversized';
    case ScriptTag = 'script_tag';
    case ForbiddenAction = 'forbidden_action';
    case UnknownAction = 'unknown_action';
    case PermissionInflation = 'permission_inflation';
    case SecretLeak = 'secret_leak';
    case CanaryLeak = 'canary_leak';
    case Timeout = 'timeout';
    case RateLimited = 'rate_limited';
    case ServerError = 'server_error';
}
