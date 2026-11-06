<?php

namespace App\Security\Scanning\Injection;

use App\Security\Scanning\Severity;

final readonly class InjectionRule
{
    public function __construct(
        public string $id,
        public string $category,
        public Severity $severity,
        public string $pattern,
    ) {}
}
