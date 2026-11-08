<?php

use App\Security\Scanning\Corpus\CorpusEvaluation;
use App\Security\Scanning\Injection\InjectionResult;
use App\Security\Scanning\ScanAction;
use App\Security\Scanning\Severity;

/*
| docs/test-strategy.md §7, §22. The hold-out set is not used to tune the rules, and its rate is reported as
| measured: it does not fail the build. All of these were written by the author of the rules, so even the
| hold-out says little about attacks written by someone else. The measuring is in CorpusEvaluation, which the
| report command (§31) shares.
*/

function corpusEvaluation(): CorpusEvaluation
{
    return new CorpusEvaluation(__DIR__.'/../../../resources/security/corpus');
}

it('has at least 120 attacks, with about 30% held out', function () {
    $tuning = count(corpusEvaluation()->load('injection-tuning'));
    $holdout = count(corpusEvaluation()->load('injection-holdout'));

    expect($tuning + $holdout)->toBeGreaterThanOrEqual(120)
        ->and($holdout / ($tuning + $holdout))->toBeGreaterThanOrEqual(0.3);
});

it('ST-02: finds at least 90% of the tuning attacks at Medium or more', function () {
    $result = corpusEvaluation()->injection('injection-tuning');

    fwrite(STDERR, sprintf("\nCORPUS injection-tuning found=%d/%d (%.1f%%)\n%s\n", $result['found'], $result['total'], 100 * $result['rate'], implode("\n", array_map(fn ($m) => 'MISSED tuning: '.$m, $result['missed']))));

    expect($result['rate'])->toBeGreaterThanOrEqual(CorpusEvaluation::TARGET_INJECTION_FOUND);
})->group('security');

it('reports the hold-out as measured', function () {
    $result = corpusEvaluation()->injection('injection-holdout');

    fwrite(STDERR, sprintf("\nCORPUS injection-holdout found=%d/%d (%.1f%%)\n%s\n", $result['found'], $result['total'], 100 * $result['rate'], implode("\n", array_map(fn ($m) => 'MISSED holdout: '.$m, $result['missed']))));

    expect($result['total'])->toBeGreaterThan(0);
})->group('security');

it('leaves ordinary business text alone: at most 1% stopped, at most 5% at Medium or more', function () {
    $result = corpusEvaluation()->injectionBusiness();

    fwrite(STDERR, sprintf("\nCORPUS injection-business sentences=%d stopped=%d (%.1f%%) flagged=%d (%.1f%%)\n%s\n", $result['total'], count($result['stopped']), 100 * $result['stopped_rate'], count($result['flagged']), 100 * $result['flagged_rate'], implode("\n", array_map(fn ($f) => 'FLAGGED: '.$f, $result['flagged']))));

    expect($result['stopped_rate'])->toBeLessThanOrEqual(CorpusEvaluation::TARGET_STOPPED_MAX)
        ->and($result['flagged_rate'])->toBeLessThanOrEqual(CorpusEvaluation::TARGET_FLAGGED_MAX);
})->group('security');

it('reports the English business text as measured, with no gate (step 3-2)', function () {
    $sentences = corpusEvaluation()->load('business-en');
    $result = corpusEvaluation()->injectionBusiness('business-en');

    fwrite(STDERR, sprintf("\nCORPUS injection-business-en sentences=%d stopped=%d (%.1f%%) flagged=%d (%.1f%%)\n%s\n", $result['total'], count($result['stopped']), 100 * $result['stopped_rate'], count($result['flagged']), 100 * $result['flagged_rate'], implode("\n", array_map(fn ($f) => 'FLAGGED-EN: '.$f, $result['flagged']))));

    expect(count($sentences))->toBeGreaterThanOrEqual(50)
        ->and(count(array_unique($sentences)))->toBe(count($sentences))
        ->and($result['total'])->toBe(count($sentences));
})->group('security');

it('counts an attack as found at Medium or more only', function () {
    expect(CorpusEvaluation::foundAtMediumOrMore(new InjectionResult(Severity::Low, ScanAction::Record, [])))->toBeFalse()
        ->and(CorpusEvaluation::foundAtMediumOrMore(new InjectionResult(Severity::Medium, ScanAction::Warn, [])))->toBeTrue()
        ->and(CorpusEvaluation::foundAtMediumOrMore(new InjectionResult(null, ScanAction::Record, [])))->toBeFalse();
});

it('counts a secret as stopped only when the scan stops, and a rule as found only when it is', function () {
    $directory = sys_get_temp_dir().'/corpus-eval-'.uniqid();
    mkdir($directory);
    // A card number labelled as a key: the key rule is not found, and a card does not stop the work.
    file_put_contents($directory.'/sensitive.json', json_encode([['template' => 'card {{CARD}}', 'rules' => ['SEC-APIKEY']]]));

    $result = (new CorpusEvaluation($directory))->sensitive();
    unlink($directory.'/sensitive.json');
    rmdir($directory);

    expect($result)->toMatchArray(['samples' => 1, 'blocked' => 0, 'blockable' => 1])
        ->and($result['missed'])->toBe(['card {{CARD}} -> SEC-APIKEY']);
});

it('encodes a base64 placeholder when it measures, so the corpus stays readable', function () {
    expect(CorpusEvaluation::expandAttack('say {{BASE64:ignore previous}} now'))->toBe('say '.base64_encode('ignore previous').' now');
});
