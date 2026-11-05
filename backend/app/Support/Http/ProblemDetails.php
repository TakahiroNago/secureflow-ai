<?php

namespace App\Support\Http;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\QueryException;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use PDOException;
use RedisException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Throwable;

/**
 * RFC 9457 errors for the authentication API (docs/api-design.md §1.1). The other errors are
 * unified in step 2-9. Details come from fixed strings, never from exception messages.
 */
final class ProblemDetails
{
    /**
     * Every 503 of the password change endpoint says this, before or after the commit. Saying it only
     * after the commit would reveal that the current password was right.
     */
    public const PASSWORD_CHANGE_UNAVAILABLE_DETAIL = 'パスワード変更の結果を確認できませんでした。変更が確定している可能性があります。できるだけ早く、同じ内容・同じ冪等性キーで再試行してください。';

    private const UNAVAILABLE_DETAIL = '現在サービスを利用できません。しばらく待ってから再度お試しください。';

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
            // Decided by exception class, never by message. A dependency failure is not AUTH_FAILED.
            $exception instanceof ServiceUnavailableException,
            $exception instanceof RedisException,
            $exception instanceof QueryException,
            $exception instanceof PDOException => self::unavailable($request),
            ! $exception instanceof HttpExceptionInterface && $request->is('api/v1/auth/*', 'api/v1/account/*', 'sanctum/*') => self::response(
                500, 'INTERNAL_ERROR', 'Internal server error', 'サーバーでエラーが発生しました。',
            ),
            default => null,
        };
    }

    private static function unavailable(Request $request): JsonResponse
    {
        return self::response(
            503,
            'SERVICE_UNAVAILABLE',
            'Service unavailable',
            $request->is('api/v1/account/password') ? self::PASSWORD_CHANGE_UNAVAILABLE_DETAIL : self::UNAVAILABLE_DETAIL,
            [],
            ['Retry-After' => (string) config()->integer('audit.db_unavailable_ttl_seconds')],
        );
    }
}
