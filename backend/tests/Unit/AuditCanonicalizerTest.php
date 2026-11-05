<?php

use App\Audit\AuditCanonicalizer;

/*
| AUDIT-HASH-01, PHP half (docs/database-design.md §3.12.3). The PostgreSQL half reads the same file:
| Feature/Audit/AuditDatabaseTest.php.
*/

function hashVectors(): array
{
    return json_decode((string) file_get_contents(__DIR__.'/../Fixtures/audit-hash-vectors.json'), true, 16, JSON_THROW_ON_ERROR);
}

function vectorFields(array $vector, array $base): array
{
    if (! ($vector['base'] ?? false)) {
        return $vector['fields'];
    }

    $fields = $base['fields'];
    $fields[8] = $vector['resource_type'] ?? null;
    $fields[14] = $vector['metadata'];
    $fields[15] = $vector['occurred_at'] ?? $fields[15];

    return $fields;
}

it('AUDIT-HASH-01: reproduces every fixed vector', function () {
    $data = hashVectors();

    foreach ($data['vectors'] as $vector) {
        expect(AuditCanonicalizer::hash(vectorFields($vector, $data['base'])))->toBe($vector['sha256'], $vector['id']);
    }
});

it('AUDIT-HASH-01: tells NULL, the empty string and a dash apart', function () {
    $hashes = array_map(fn (?string $value) => AuditCanonicalizer::hash(['a', $value]), [null, '', '-']);

    expect(array_unique($hashes))->toHaveCount(3);
});

it('AUDIT-HASH-01: counts length in bytes, and does not normalize Unicode', function () {
    expect(AuditCanonicalizer::canonical(['認証']))->toBe('secureflow.audit.v1|6:認証')
        ->and(AuditCanonicalizer::canonical(["\u{1F600}"]))->toStartWith('secureflow.audit.v1|4:')
        ->and(AuditCanonicalizer::hash(["\u{E9}"]))->not->toBe(AuditCanonicalizer::hash(["e\u{301}"]));
});

it('AUDIT-HASH-01: builds the canonical JSON the way jsonb renders it', function () {
    $data = hashVectors();
    $canonical = AuditCanonicalizer::metadata($data['metadata_only']['input']);

    expect(hash('sha256', $canonical))->toBe($data['metadata_only']['sha256'])
        ->and(AuditCanonicalizer::metadata('[]'))->toBe('{}')
        ->and(AuditCanonicalizer::metadata('{}'))->toBe('{}')
        ->and(AuditCanonicalizer::metadata('{"b":1,"aa":"x","aa":"y"}'))->toBe('{"b": 1, "aa": "y"}');
});
