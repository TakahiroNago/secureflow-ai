<?php

namespace App\Http\Requests;

use App\Domain\Security\FindingStatus;
use App\Domain\Security\FindingStatusChanger;
use App\Security\Output\AiTaskSchema;
use Closure;
use Illuminate\Validation\Rule;

/**
 * docs/api-design.md §3.7. The note is checked here for its shape, and scanned afterwards like any other text.
 */
final class UpdateFindingStatusRequest extends StrictFormRequest
{
    /**
     * @return array<string, mixed>
     */
    public function rules(): array
    {
        return [
            'status' => ['required', Rule::enum(FindingStatus::class)],
            'status_note' => ['sometimes', 'nullable', 'string', function (string $attribute, mixed $value, Closure $fail): void {
                if ($value !== null && AiTaskSchema::textProblem($value, FindingStatusChanger::NOTE_LIMIT) !== null) {
                    $fail('入力内容を確認してください。');
                }
            }],
        ];
    }

    public function status(): FindingStatus
    {
        return FindingStatus::from($this->string('status')->toString());
    }

    /**
     * An empty note is no note.
     */
    public function note(): ?string
    {
        $note = $this->input('status_note');

        return is_string($note) && $note !== '' ? $note : null;
    }
}
