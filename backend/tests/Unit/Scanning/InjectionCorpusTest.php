<?php

use App\Security\Scanning\Injection\InjectionHit;
use App\Security\Scanning\Injection\InjectionResult;
use App\Security\Scanning\Injection\InjectionScanner;

/*
| docs/test-strategy.md §7, §22. The hold-out set is not used to tune the rules, and its rate is reported as
| measured: it does not fail the build. All of these were written by the author of the rules, so even the
| hold-out says little about attacks written by someone else.
*/

function injectionCorpus(string $name): array
{
    $path = __DIR__.'/../../../resources/security/corpus/'.$name.'.json';

    return json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
}

function expandedAttack(string $attack): string
{
    return (string) preg_replace_callback('/\{\{BASE64:(.*?)\}\}/u', fn (array $m) => base64_encode($m[1]), $attack);
}

function foundAtMediumOrMore(InjectionResult $result): bool
{
    return $result->severity !== null && $result->severity->rank() >= 2;
}

/**
 * @return array{found: int, total: int, missed: list<string>}
 */
function measureAttacks(string $name): array
{
    $scanner = new InjectionScanner;
    $attacks = injectionCorpus($name);
    $missed = array_values(array_filter($attacks, fn (string $attack) => ! foundAtMediumOrMore($scanner->scan(expandedAttack($attack)))));

    return ['found' => count($attacks) - count($missed), 'total' => count($attacks), 'missed' => $missed];
}

it('has at least 120 attacks, with about 30% held out', function () {
    $tuning = count(injectionCorpus('injection-tuning'));
    $holdout = count(injectionCorpus('injection-holdout'));

    expect($tuning + $holdout)->toBeGreaterThanOrEqual(120)
        ->and($holdout / ($tuning + $holdout))->toBeGreaterThanOrEqual(0.3);
});

it('finds at least 90% of the tuning attacks at Medium or more', function () {
    $result = measureAttacks('injection-tuning');

    fwrite(STDERR, sprintf("\nCORPUS injection-tuning found=%d/%d (%.1f%%)\n%s\n", $result['found'], $result['total'], 100 * $result['found'] / $result['total'], implode("\n", array_map(fn ($m) => 'MISSED tuning: '.$m, $result['missed']))));

    expect($result['found'] / $result['total'])->toBeGreaterThanOrEqual(0.9);
});

it('reports the hold-out as measured', function () {
    $result = measureAttacks('injection-holdout');

    fwrite(STDERR, sprintf("\nCORPUS injection-holdout found=%d/%d (%.1f%%)\n%s\n", $result['found'], $result['total'], 100 * $result['found'] / $result['total'], implode("\n", array_map(fn ($m) => 'MISSED holdout: '.$m, $result['missed']))));

    expect($result['total'])->toBeGreaterThan(0);
});

it('leaves ordinary business text alone: at most 1% stopped, at most 5% at Medium or more', function () {
    $scanner = new InjectionScanner;
    $sentences = injectionCorpus('business');
    $stopped = $flagged = [];

    foreach ($sentences as $sentence) {
        $result = $scanner->scan($sentence);
        $rules = implode(',', array_map(fn (InjectionHit $hit) => $hit->ruleId, $result->hits));

        if ($result->blocks()) {
            $stopped[] = $sentence.' -> '.$rules;
        }
        if (foundAtMediumOrMore($result)) {
            $flagged[] = $sentence.' -> '.$rules;
        }
    }

    $total = count($sentences);

    fwrite(STDERR, sprintf("\nCORPUS injection-business sentences=%d stopped=%d (%.1f%%) flagged=%d (%.1f%%)\n%s\n", $total, count($stopped), 100 * count($stopped) / $total, count($flagged), 100 * count($flagged) / $total, implode("\n", array_map(fn ($f) => 'FLAGGED: '.$f, $flagged))));

    expect(count($stopped) / $total)->toBeLessThanOrEqual(0.01)
        ->and(count($flagged) / $total)->toBeLessThanOrEqual(0.05);
});
