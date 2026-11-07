<?php

use Illuminate\Support\Facades\File;
use Tests\Support\SecurityTestIndex;

/*
| ST-GROUP-01 (docs/test-strategy.md §31): the security tests are one group, `pest --group security`, whatever
| directory they live in. Every case of docs/test-strategy.md §5 has a test in it, and a test named after a case
| cannot fall out of it.
*/

/** The cases of docs/test-strategy.md §5, ST-01 to this number. */
const ST_CASES = 39;

/** The Security directory is in the group by Pest.php; anything else needs the chained call. */
function stGrouped(string $relative, string $chain): bool
{
    return str_starts_with($relative, 'tests/Security/') || SecurityTestIndex::inGroup($chain);
}

/**
 * @return list<array{file: string, case: int, name: string, grouped: bool}>
 */
function stDeclarations(): array
{
    $out = [];

    foreach (File::allFiles(base_path('tests')) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $relative = str_replace('\\', '/', substr($file->getPathname(), strlen(base_path()) + 1));

        foreach (SecurityTestIndex::declarations((string) file_get_contents($file->getPathname())) as $declaration) {
            if (preg_match('/^ST-(\d{2})\b/', $declaration['name'], $match) !== 1) {
                continue;
            }

            $out[] = [
                'file' => $relative,
                'case' => (int) $match[1],
                'name' => $declaration['name'],
                'grouped' => stGrouped($relative, $declaration['chain']),
            ];
        }
    }

    return $out;
}

it('ST-GROUP-01: every ST case has at least one test in the security group', function () {
    $cases = collect(stDeclarations())->where('grouped', true)->pluck('case')->unique()->sort()->values()->all();

    expect($cases)->toBe(range(1, ST_CASES));
});

it('ST-GROUP-01: a test named after an ST case is in the group, wherever it lives', function () {
    $outside = collect(stDeclarations())
        ->where('grouped', false)
        ->map(fn (array $declaration) => $declaration['file'].': '.$declaration['name'])
        ->values()
        ->all();

    expect($outside)->toBe([]);
});

it('reads declarations by tokens, so parentheses and quotes inside strings do not confuse it', function () {
    $source = <<<'PHP'
    <?php
    it('ST-99: a (tricky) name with \'quotes\'', function () {
        expect(')')->toBe(')'); // it('not a test')
    })->with(['a', 'b)']);
    it("ST-98: tagged", fn () => null)->with([1])->group('security');
    test('ST-97: double quoted group', fn () => null)->group("security", 'slow');
    it('ST-96: another group that contains the word', fn () => null)->group('not-security');
    $x->it('ignored: a method');
    PHP;

    $declarations = SecurityTestIndex::declarations($source);

    expect(array_column($declarations, 'name'))->toBe(['ST-99: a (tricky) name with \'quotes\'', 'ST-98: tagged', 'ST-97: double quoted group', 'ST-96: another group that contains the word'])
        ->and(SecurityTestIndex::inGroup($declarations[0]['chain']))->toBeFalse()
        ->and(SecurityTestIndex::inGroup($declarations[1]['chain']))->toBeTrue()
        ->and(SecurityTestIndex::inGroup($declarations[2]['chain']))->toBeTrue()
        ->and(SecurityTestIndex::inGroup($declarations[3]['chain']))->toBeFalse()
        ->and(substr($source, $declarations[0]['end'], 1))->toBe(';');
});

it('counts the Security directory as the group, and nothing else without the chained call', function () {
    expect(stGrouped('tests/Security/SomethingTest.php', ''))->toBeTrue()
        ->and(stGrouped('tests/Feature/SomethingTest.php', ''))->toBeFalse()
        ->and(stGrouped('tests/Feature/SomethingTest.php', "->with([1])->group('security')"))->toBeTrue()
        ->and(stGrouped('tests/Feature/SomethingTest.php', "->group('not-security')"))->toBeFalse()
        ->and(stGrouped('tests/SecurityHelpers/SomethingTest.php', ''))->toBeFalse();
});
