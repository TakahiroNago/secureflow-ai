<?php

namespace App\Support\Http;

use App\Domain\Security\InputBlockedException;
use App\Domain\Workflow\RiskAcknowledgementRequiredException;
use App\Domain\Workflow\WorkflowConflictException;
use App\Http\Resources\ScanStatus;
use Illuminate\Auth\Access\AuthorizationException;
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
 * RFC 9457 errors for the authentication and workflow APIs (docs/api-design.md §1.1). The other errors
 * are unified in step 2-9. Details come from fixed strings, never from exception messages.
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
            $exception instanceof InputBlockedException => self::inputBlocked($exception),
            $exception instanceof ValidationException => self::response(
                422, 'VALIDATION_FAILED', 'Validation failed', '入力内容を確認してください。', $exception->errors(),
            ),
            $exception instanceof ThrottleRequestsException => self::response(
                429, 'RATE_LIMITED', 'Too many requests', 'しばらく待ってから再度お試しください。', [], $exception->getHeaders(),
            ),
            $exception instanceof HttpExceptionInterface && $exception->getStatusCode() === 419 => self::response(
                419, 'CSRF_TOKEN_MISMATCH', 'CSRF token mismatch', 'ページを再読み込みしてください。',
            ),
            $exception instanceof WorkflowConflictException => self::response(
                409, $exception->problemCode, 'Conflict', $exception->detail,
            ),
            $exception instanceof RiskAcknowledgementRequiredException => self::response(
                422, 'RISK_ACK_REQUIRED', 'Risk acknowledgement required', 'リスクを確認してから承認してください。',
            ),
            $exception instanceof PreconditionRequiredException => self::response(
                428, 'PRECONDITION_REQUIRED', 'Precondition required', 'If-Match ヘッダに現在のリビジョン番号を指定してください。',
            ),
            $exception instanceof HttpExceptionInterface && $exception->getStatusCode() === 403 && $request->is('api/v1/*') => self::forbidden($exception),
            // Laravel has already turned a missing model into this, so the message names no model or id.
            $exception instanceof HttpExceptionInterface && $exception->getStatusCode() === 404 && $request->is('api/v1/*') => self::response(
                404, 'NOT_FOUND', 'Not found', '対象が見つかりません。',
            ),
            // Decided by exception class, never by message. A dependency failure is not AUTH_FAILED.
            $exception instanceof ServiceUnavailableException,
            $exception instanceof RedisException,
            $exception instanceof QueryException,
            $exception instanceof PDOException => self::unavailable($request),
            ! $exception instanceof HttpExceptionInterface && $request->is('api/v1/auth/*', 'api/v1/account/*', 'api/v1/analyses*', 'api/v1/workflows*', 'api/v1/approvals*', 'api/v1/security/*', 'sanctum/*') => self::response(
                500, 'INTERNAL_ERROR', 'Internal server error', 'サーバーでエラーが発生しました。',
            ),
            default => null,
        };
    }

    /**
     * No masked text: the surroundings of a secret are not to be sent back either (docs/api-design.md §3.3).
     */
    private static function inputBlocked(InputBlockedException $exception): JsonResponse
    {
        $response = self::response(422, 'INPUT_BLOCKED', 'Input blocked', $exception->detail());
        $response->setData([...(array) $response->getData(true), 'scan' => ScanStatus::ofResult($exception->result)]);

        return $response;
    }

    /**
     * The code comes from the policy that refused. Its message is not shown.
     */
    private static function forbidden(Throwable $exception): JsonResponse
    {
        $previous = $exception->getPrevious();
        $refusal = $previous instanceof AuthorizationException ? $previous->response() : null;

        return match ($refusal?->code()) {
            'APPROVER_ROLE_REQUIRED' => self::response(403, 'APPROVER_ROLE_REQUIRED', 'Forbidden', '承認または却下する権限がありません。'),
            'SELF_APPROVAL_FORBIDDEN' => self::response(403, 'SELF_APPROVAL_FORBIDDEN', 'Forbidden', '自分が作成したワークフローは承認または却下できません。'),
            default => self::response(403, 'FORBIDDEN', 'Forbidden', 'この操作を行う権限がありません。'),
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
