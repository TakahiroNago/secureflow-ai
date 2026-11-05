<?php

use Illuminate\Database\Connection;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Str;

/*
| DB-CON-01 (docs/test-strategy.md §13). Runs as the application role.
| The SQLSTATE proves which constraint rejected the row: 23502 not-null, 23514 check,
| 23505 unique, 23503 foreign key.
*/

uses(DatabaseTransactions::class);

function sqlStateOf(Closure $statement): ?string
{
    return dbError(appDb(), $statement)?->getCode();
}

it('accepts valid rows', function () {
    $organization = insertOrganization(appDb());
    $user = insertUser(appDb(), $organization);
    insertSettings(appDb(), $organization, ['updated_by' => $user]);

    $row = appDb()->table('users')->where('id', $user)->first();
    $settings = appDb()->table('organization_settings')->where('organization_id', $organization)->first();

    expect($row->is_active)->toBeTrue()
        ->and($row->failed_login_count)->toBe(0)
        ->and($settings->max_input_chars)->toBe(4000);
});

it('rejects NULL in the enum columns', function (Closure $statement) {
    expect(sqlStateOf($statement))->toBe('23502');
})->with([
    'users.role' => fn (Connection $db) => insertUser($db, insertOrganization($db), ['role' => null]),
]);

it('rejects bad audit rows even from the owner', function (Closure $statement, string $sqlState) {
    expect(dbError(ownerDb(), $statement)?->getCode())->toBe($sqlState);
})->with([
    'NULL actor_type' => [fn (Connection $db) => insertAuditLog($db, actorType: null), '23502'],
    'NULL result' => [fn (Connection $db) => insertAuditLog($db, result: null), '23502'],
    'unknown actor_type' => [fn (Connection $db) => insertAuditLog($db, actorType: 'root'), '23514'],
    'unknown result' => [fn (Connection $db) => insertAuditLog($db, result: 'maybe'), '23514'],
]);

it('rejects values outside the enums', function (Closure $statement) {
    expect(sqlStateOf($statement))->toBe('23514');
})->with([
    'users.role' => fn (Connection $db) => insertUser($db, insertOrganization($db), ['role' => 'root']),
]);

it('accepts every designed enum value', function (string $role) {
    expect(sqlStateOf(fn (Connection $db) => insertUser($db, insertOrganization($db), ['role' => $role])))->toBeNull();
})->with(['admin', 'member', 'auditor']);

it('rejects settings outside their ranges', function (array $overrides) {
    expect(sqlStateOf(fn (Connection $db) => insertSettings($db, insertOrganization($db), $overrides)))->toBe('23514');
})->with([
    'monthly limit zero' => [['monthly_token_limit' => 0]],
    'daily limit zero' => [['user_daily_request_limit' => 0]],
    'input below range' => [['max_input_chars' => 0]],
    'input above range' => [['max_input_chars' => 20001]],
]);

it('accepts settings on the range boundaries', function (int $chars) {
    expect(sqlStateOf(fn (Connection $db) => insertSettings($db, insertOrganization($db), ['max_input_chars' => $chars])))->toBeNull();
})->with([1, 20000]);

it('treats email addresses differing only by case as duplicates', function () {
    $organization = insertOrganization(appDb());
    insertUser(appDb(), $organization, ['email' => 'taken@example.com']);

    expect(sqlStateOf(fn (Connection $db) => insertUser($db, $organization, ['email' => 'TAKEN@EXAMPLE.COM'])))->toBe('23505');
});

it('rejects raw inserts that leave out the id, because the database generates no id', function (string $statement) {
    expect(sqlStateOf(fn (Connection $db) => $db->statement($statement)))->toBe('23502');
})->with([
    'organizations' => ["INSERT INTO organizations (name, created_at, updated_at) VALUES ('x', now(), now())"],
    'users' => ["INSERT INTO users (organization_id, name, email, password, role, created_at, updated_at)
                VALUES ('00000000-0000-7000-8000-000000000000', 'x', 'x@example.com', 'x', 'member', now(), now())"],
]);

it('has no database default for UUID primary keys', function (string $table) {
    $row = appDb()->selectOne(
        "SELECT column_default FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = ? AND column_name = 'id'",
        [$table],
    );

    expect($row->column_default)->toBeNull();
})->with(['organizations', 'users']);

it('rejects references to rows that do not exist', function (Closure $statement) {
    expect(sqlStateOf($statement))->toBe('23503');
})->with([
    'user organization' => fn (Connection $db) => insertUser($db, (string) Str::uuid7()),
    'settings organization' => fn (Connection $db) => insertSettings($db, (string) Str::uuid7()),
    'settings updated_by' => fn (Connection $db) => insertSettings($db, insertOrganization($db), ['updated_by' => (string) Str::uuid7()]),
]);

it('rejects a duplicate audit event id', function () {
    $values = auditValues();
    $sql = 'INSERT INTO audit_logs ('.AUDIT_INSERT_COLUMNS.') VALUES ('.AUDIT_INSERT_PLACEHOLDERS.')';
    ownerDb()->insert($sql, $values);

    expect(dbError(ownerDb(), fn (Connection $db) => $db->insert($sql, $values))?->getCode())->toBe('23505');
});
