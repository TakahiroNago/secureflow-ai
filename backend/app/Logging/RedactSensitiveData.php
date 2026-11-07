<?php

namespace App\Logging;

use App\Security\Scanning\SensitiveDataScanner;
use App\Support\Http\RequestId;
use Monolog\LogRecord;
use Monolog\Processor\ProcessorInterface;
use Throwable;

/**
 * The last check before a line leaves (docs/security-design.md §17). Code here already avoids logging text, so this is
 * for what slips through. Strings go through the same detectors as an input: personal data is masked, and a secret, or
 * anything that could not be checked, takes the whole string with it.
 *
 * An exception keeps its class and place but not its message, which can hold SQL or an input a detector cannot recognize.
 * Each line carries the trace id that the answer to the request has.
 */
final class RedactSensitiveData implements ProcessorInterface
{
    public const REDACTED = '[REDACTED]';

    private const MAX_CHARACTERS = 4000;

    private const MAX_DEPTH = 6;

    private readonly SensitiveDataScanner $scanner;

    public function __construct(?SensitiveDataScanner $scanner = null)
    {
        $this->scanner = $scanner ?? new SensitiveDataScanner;
    }

    public function __invoke(LogRecord $record): LogRecord
    {
        try {
            /** @var array<string, mixed> $context */
            $context = $this->value($record->context, 0);
            /** @var array<string, mixed> $extra */
            $extra = $this->value($record->extra, 0);

            return $record->with(
                message: $this->text($record->message),
                context: $context,
                extra: [...$extra, 'trace_id' => app(RequestId::class)->value()],
            );
        } catch (Throwable) {
            return $record->with(message: self::REDACTED, context: [], extra: []);
        }
    }

    private function value(mixed $value, int $depth): mixed
    {
        return match (true) {
            is_string($value) => $this->text($value),
            is_array($value) => $depth >= self::MAX_DEPTH
                ? self::REDACTED
                : array_map(fn (mixed $item) => $this->value($item, $depth + 1), $value),
            $value instanceof Throwable => $this->throwable($value),
            is_object($value) => '['.$value::class.']',
            default => $value,
        };
    }

    /**
     * @return array<string, mixed>
     */
    private function throwable(Throwable $exception): array
    {
        return [
            'class' => $exception::class,
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'trace' => mb_substr($exception->getTraceAsString(), 0, self::MAX_CHARACTERS, 'UTF-8'),
            'previous' => $exception->getPrevious()?->__toString() === null ? null : $exception->getPrevious()::class,
        ];
    }

    private function text(string $text): string
    {
        $short = mb_strlen($text, 'UTF-8') > self::MAX_CHARACTERS
            ? mb_substr($text, 0, self::MAX_CHARACTERS, 'UTF-8').'…'
            : $text;

        return $this->scanner->scan($short)->maskedText ?? self::REDACTED;
    }
}
