<?php

namespace App\Support\Http;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Throwable;

/**
 * RFC 9457 errors for the authentication API (docs/api-design.md §1.1). The other errors are
 * unified in step 2-9. Details come from fixed strings, never from exception messages.
 */
final class ProblemDetails
{
    /**
     * @param  array<array-key, mixed>  $errors
     * @param  array<string, mixed>  $headers
     */
    public static function response(int $status, string $code, string $title, string $detail, array $errors = [], array $headers = []): JsonResponse
    {
        $body = [
            'type' => 'https://secureflow.local/problems/'.Str::of($code)->lower()->replace('_', '-'),
            'title' => $title,
            'status' => $status,
            'code' => $code,
            'detail' => $detail,
            'trace_id' => (string) Str::uuid7(),
        ];

        if ($errors !== []) {
            $body['errors'] = $errors;
        }

        return new JsonResponse($body, $status, ['Content-Type' => 'application/problem+json', ...$headers], JSON_UNESCAPED_UNICODE);
    }

    public static function authFailed(): JsonResponse
    {
        return self::response(401, 'AUTH_FAILED', 'Authentication failed', 'メールアドレスまたはパスワードが正しくありません。');
    }

    public static function fromThrowable(Throwable $exception, Request $request): ?JsonResponse
    {
        if (! $request->is('api/*', 'sanctum/*')) {
            return null;
        }

        return match (true) {
            $exception instanceof AuthenticationException => self::response(
                401, 'UNAUTHENTICATED', 'Unauthenticated', 'ログインしてください。',
            ),
            $exception instanceof ValidationException => self::response(
                422, 'VALIDATION_FAILED', 'Validation failed', '入力内容を確認してください。', $exception->errors(),
            ),
            $exception instanceof ThrottleRequestsException => self::response(
                429, 'RATE_LIMITED', 'Too many requests', 'しばらく待ってから再度お試しください。', [], $exception->getHeaders(),
            ),
            $exception instanceof HttpExceptionInterface && $exception->getStatusCode() === 419 => self::response(
                419, 'CSRF_TOKEN_MISMATCH', 'CSRF token mismatch', 'ページを再読み込みしてください。',
            ),
            default => null,
        };
    }
}
