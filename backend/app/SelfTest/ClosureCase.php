<?php

namespace App\SelfTest;

use Closure;

/**
 * A case written as a closure, so that the families in Cases/ stay short.
 */
final readonly class ClosureCase implements SelfTestCase
{
    /**
     * @param  Closure(SelfTestContext): CaseOutcome  $run
     */
    public function __construct(
        private string $id,
        private string $category,
        private string $name,
        private string $expected,
        private Closure $run,
        private bool $isolated = true,
    ) {}

    public function id(): string
    {
        return $this->id;
    }

    public function category(): string
    {
        return $this->category;
    }

    public function name(): string
    {
        return $this->name;
    }

    public function expected(): string
    {
        return $this->expected;
    }

    public function isolated(): bool
    {
        return $this->isolated;
    }

    public function run(SelfTestContext $context): CaseOutcome
    {
        return ($this->run)($context);
    }
}
