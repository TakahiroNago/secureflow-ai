<?php

namespace Tests\Support;

use App\Security\Scanning\Corpus\SecretTemplates;

/**
 * Secrets for tests, built when they run (docs/test-strategy.md §21). The generator lives with the corpus
 * evaluation since step 3-1, so that the report command expands the same templates the tests do.
 */
final class FakeSecrets extends SecretTemplates {}
