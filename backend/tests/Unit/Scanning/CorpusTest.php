<?php

use App\Security\Scanning\Detection;
use App\Security\Scanning\ScanAction;
use App\Security\Scanning\ScanDecision;
use App\Security\Scanning\SensitiveDataScanner;
use Tests\Support\FakeSecrets;

/*
| docs/test-strategy.md §7, §21. The targets are on this corpus, and say nothing about text not in it. The
| business sentences were written by the author of the rules, so they may share its blind spots.
*/

function corpus(string $name): array
{
    $path = __DIR__.'/../../../resources/security/corpus/'.$name.'.json';

    return json_decode((string) file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
}

function ruleIds(array $detections): array
{
    return array_map(fn (Detection $detection) => $detection->rule->value, $detections);
}

beforeEach(fn () => mt_srand(20261106));

it('has enough sentences to measure a rate of 1%', function () {
    expect(count(corpus('business')))->toBeGreaterThanOrEqual(200)
        ->and(count(array_unique(corpus('business'))))->toBe(count(corpus('business')));
});

it('holds nothing shaped like a secret: they are built when the test runs', function () {
    $raw = (string) file_get_contents(__DIR__.'/../../../resources/security/corpus/sensitive.json');

    expect($raw)->not->toMatch('/AK'.'IA[0-9A-Z]{16}|gh'.'p_[A-Za-z0-9]{36}|-----BE'.'GIN|ey'.'J[A-Za-z0-9_-]{8}/');
});

it('finds every sensitive sample: 100% of the formats, 100% of the secrets blocked', function () {
    $samples = corpus('sensitive');
    $missed = [];
    $blocked = $blockable = 0;

    foreach ($samples as $sample) {
        $text = FakeSecrets::expand($sample['template']);
        $result = (new SensitiveDataScanner)->scan($text);
        $found = ruleIds($result->detections);

        foreach ($sample['rules'] as $rule) {
            if (! in_array($rule, $found, true)) {
                $missed[] = $sample['template'].' -> '.$rule;
            }
        }

        if (str_starts_with($sample['rules'][0], 'SEC-') && $sample['rules'][0] !== 'SEC-ENTROPY') {
            $blockable++;
            $blocked += $result->decision === ScanDecision::Block ? 1 : 0;
        }
    }

    fwrite(STDERR, sprintf("\nCORPUS sensitive samples=%d missed=%d blocked=%d/%d\n", count($samples), count($missed), $blocked, $blockable));

    expect($missed)->toBe([])->and($blocked)->toBe($blockable);
});

it('leaves ordinary business text alone: at most 1% stopped, at most 5% with a detection of medium or more', function () {
    $sentences = corpus('business');
    $stopped = $flagged = [];

    foreach ($sentences as $sentence) {
        $result = (new SensitiveDataScanner)->scan($sentence);

        if ($result->decision === ScanDecision::Block) {
            $stopped[] = $sentence;
        }
        if ($result->detections !== []) {
            $flagged[] = $sentence.' -> '.implode(',', ruleIds($result->detections));
        }
    }

    $total = count($sentences);

    fwrite(STDERR, sprintf("\nCORPUS business sentences=%d stopped=%d (%.1f%%) flagged=%d (%.1f%%)\n%s\n", $total, count($stopped), 100 * count($stopped) / $total, count($flagged), 100 * count($flagged) / $total, implode("\n", $flagged)));

    expect(count($stopped) / $total)->toBeLessThanOrEqual(0.01)
        ->and(count($flagged) / $total)->toBeLessThanOrEqual(0.05);
});

it('blocks nothing in the corpus by a rule that only warns or masks', function () {
    foreach (corpus('sensitive') as $sample) {
        if (! str_starts_with($sample['rules'][0], 'PII-')) {
            continue;
        }

        $result = (new SensitiveDataScanner)->scan(FakeSecrets::expand($sample['template']));

        foreach ($result->detections as $detection) {
            expect($detection->rule->action())->toBe(ScanAction::MaskContinue);
        }
    }
});
