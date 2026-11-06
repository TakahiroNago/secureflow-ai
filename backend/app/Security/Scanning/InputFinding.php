<?php

namespace App\Security\Scanning;

/**
 * One finding, ready to store or show. Positions are in the masked text, or in the text as typed when the
 * scan stopped, because then there is no masked text. The field is null for a single text.
 */
final readonly class InputFinding
{
    public function __construct(
        public string $category,
        public string $ruleId,
        public Severity $severity,
        public ScanAction $action,
        public string $message,
        public ?int $start,
        public ?int $end,
        public ?string $field,
        public ?string $excerpt,
    ) {}

    public function withoutExcerpt(): self
    {
        return new self($this->category, $this->ruleId, $this->severity, $this->action, $this->message, $this->start, $this->end, $this->field, null);
    }

    /**
     * What the API shows. The excerpt is for the security screen, so it is not here.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'category' => $this->category,
            'rule_id' => $this->ruleId,
            'severity' => $this->severity->value,
            'action' => $this->action->value,
            'message' => $this->message,
            'field' => $this->field,
            'position_start' => $this->start,
            'position_end' => $this->end,
        ];
    }
}
