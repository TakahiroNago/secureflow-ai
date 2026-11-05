<?php

use App\Security\Policy\ActionCatalog;
use App\Security\Policy\PolicyDecision;

/*
| AI-CAT-01. The table of docs/architecture.md §8, written out again on purpose: a change to the catalog
| has to be a deliberate change here too.
*/

it('AI-CAT-01: lists exactly the documented actions, decisions and permissions', function (string $type, PolicyDecision $decision, array $permissions) {
    expect(ActionCatalog::has($type))->toBeTrue()
        ->and(ActionCatalog::decision($type))->toBe($decision)
        ->and(ActionCatalog::permissions($type))->toBe($permissions);
})->with([
    ['text.analyze', PolicyDecision::Allowed, ['ai.text.read']],
    ['text.summarize', PolicyDecision::Allowed, ['ai.text.read']],
    ['report.draft', PolicyDecision::Allowed, ['ai.text.read', 'report.draft.write']],
    ['task.create', PolicyDecision::Allowed, ['task.write']],
    ['email.send', PolicyDecision::Forbidden, ['external.email.send']],
    ['file.delete', PolicyDecision::Forbidden, ['file.delete']],
    ['shell.exec', PolicyDecision::Forbidden, ['system.shell']],
    ['db.query', PolicyDecision::Forbidden, ['system.database']],
    ['http.request', PolicyDecision::Forbidden, ['external.http']],
]);

it('AI-CAT-01: has nothing else, and a version', function () {
    expect(ActionCatalog::types())->toHaveCount(9)
        ->and(ActionCatalog::VERSION)->toBe('2026.11.1');
});

it('AI-CAT-01: knows nothing about a type that is not listed', function (string $type) {
    expect(ActionCatalog::has($type))->toBeFalse()
        ->and(ActionCatalog::decision($type))->toBeNull()
        ->and(ActionCatalog::permissions($type))->toBe([]);
})->with(['payment.transfer', '', 'EMAIL.SEND', 'Text.Analyze', ' text.analyze', 'text.analyze ', 'text.analyze.', '__construct']);
