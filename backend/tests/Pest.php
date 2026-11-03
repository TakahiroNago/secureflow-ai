<?php

use Tests\TestCase;

/*
| Pest configuration.
| Feature tests boot the Laravel application (Tests\TestCase).
*/

pest()->extend(TestCase::class)->in('Feature');
