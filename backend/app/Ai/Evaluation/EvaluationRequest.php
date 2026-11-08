<?php

namespace App\Ai\Evaluation;

use App\Security\Policy\ActionCatalog;
use App\Security\Policy\PolicyDecision;
use InvalidArgumentException;

/**
 * One request of the evaluation set (docs/test-strategy.md §34): what is sent, and what would count as the AI
 * doing what was asked, or, for an attack, what the injected text asked.
 */
final readonly class EvaluationRequest
{
    public const KIND_NORMAL = 'normal';

    public const KIND_ATTACK = 'attack';

    /**
     * @param  list<string>  $expected  The action types that are acceptable.
     * @param  list<string>  $required  The action types that must be chosen.
     * @param  list<string>  $followedText  Patterns that, in the text the AI wrote, mean it did what the attack asked.
     * @param  string|null  $followedLanguage  The language the attack demands; 'ja' or 'en'.
     */
    public function __construct(
        public string $id,
        public string $kind,
        public string $lang,
        public string $text,
        public array $expected,
        public array $required,
        public ?string $goal,
        public array $followedText,
        public ?string $followedLanguage,
    ) {}

    /**
     * @param  array<string, mixed>  $data
     *
     * @throws InvalidArgumentException when the entry is not what the set promises
     */
    public static function fromArray(array $data): self
    {
        $id = self::string($data, 'id');
        $kind = self::string($data, 'kind');
        $lang = self::string($data, 'lang');

        if (! in_array($kind, [self::KIND_NORMAL, self::KIND_ATTACK], true)) {
            throw new InvalidArgumentException($id.': kind must be normal or attack');
        }
        if (! in_array($lang, ['ja', 'en'], true)) {
            throw new InvalidArgumentException($id.': lang must be ja or en');
        }

        $expected = self::actions($data['expected'] ?? self::allowedTypes(), $id, 'expected');
        $required = self::actions($data['required'] ?? [], $id, 'required');

        if (array_diff($required, $expected) !== []) {
            throw new InvalidArgumentException($id.': required must be within expected');
        }

        $followed = $data['followed'] ?? [];
        if (! is_array($followed)) {
            throw new InvalidArgumentException($id.': followed must be an object');
        }
        $followedText = $followed['text'] ?? [];
        if (! is_array($followedText) || $followedText !== array_values(array_filter($followedText, 'is_string'))) {
            throw new InvalidArgumentException($id.': followed.text must be a list of patterns');
        }
        foreach ($followedText as $pattern) {
            if (@preg_match('/'.$pattern.'/iu', '') === false) {
                throw new InvalidArgumentException($id.': followed.text has an invalid pattern');
            }
        }
        $followedLanguage = $followed['language'] ?? null;
        if ($followedLanguage !== null && ! in_array($followedLanguage, ['ja', 'en'], true)) {
            throw new InvalidArgumentException($id.': followed.language must be ja or en');
        }

        $goal = $data['goal'] ?? null;

        return new self(
            $id,
            $kind,
            $lang,
            self::string($data, 'text'),
            $expected,
            $required,
            is_string($goal) ? $goal : null,
            $followedText,
            $followedLanguage,
        );
    }

    public function isAttack(): bool
    {
        return $this->kind === self::KIND_ATTACK;
    }

    /**
     * What an attack may make the AI choose without that being the attack's doing: the allowed actions.
     *
     * @return list<string>
     */
    public static function allowedTypes(): array
    {
        return array_values(array_filter(ActionCatalog::types(), fn (string $type) => ActionCatalog::decision($type) === PolicyDecision::Allowed));
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private static function string(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        if (! is_string($value) || trim($value) === '') {
            throw new InvalidArgumentException(($data['id'] ?? '?').': '.$key.' must be a non-empty string');
        }

        return $value;
    }

    /**
     * @return list<string>
     */
    private static function actions(mixed $value, string $id, string $key): array
    {
        if (! is_array($value)) {
            throw new InvalidArgumentException($id.': '.$key.' must be a list of action types');
        }

        $actions = [];
        foreach ($value as $action) {
            if (! is_string($action) || ! in_array($action, ActionCatalog::types(), true)) {
                throw new InvalidArgumentException($id.': '.$key.' names an action type that is not in the catalog');
            }
            $actions[] = $action;
        }

        return array_values(array_unique($actions));
    }
}
