<?php

use App\Models\Organization;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Event;

/*
| ST-28 over HTTP. Real commits: the verifier reads its own snapshot on its own connection, so this file cannot use
| DatabaseTransactions. Each test starts from empty audit tables and leaves them empty.
*/

const AUDIT_VERIFY = '/api/v1/audit-logs/verify';

function tamperChain(string $organizationId, string $statement): void
{
    $db = ownerDb();
    $db->statement('ALTER TABLE audit_logs DISABLE TRIGGER USER');
    $db->statement(str_replace(':org', $organizationId, $statement));
    $db->statement('ALTER TABLE audit_logs ENABLE TRIGGER USER');
}

beforeEach(function () {
    resetAuditTables();
    $this->org = Organization::factory()->create();
    $this->admin = userIn($this->org->id, 'admin');
    $this->client = loggedIn($this, $this->admin);
    foreach (range(1, 3) as $n) {
        appendAudit(['organization' => $this->org->id, 'metadata' => '{"n":'.$n.'}']);
    }
});

afterEach(function () {
    resetAuditTables();
    ownerDb()->table('users')->where('id', $this->admin->id)->delete();
    ownerDb()->table('organizations')->where('id', $this->org->id)->delete();
});

it('ST-28: says an untouched chain is valid, and only what is designed', function () {
    $response = $this->client->send('POST', AUDIT_VERIFY)->assertOk();

    expect($response->json('data'))->toBe(['valid' => true, 'checked_count' => 4, 'first_broken_seq' => null, 'reason_code' => null]);
});

it('ST-28: finds a changed row, answers 200, and leaves the record where the organization cannot read it', function () {
    $logged = [];
    Event::listen(MessageLogged::class, function (MessageLogged $message) use (&$logged): void {
        $logged[] = [$message->level, $message->message];
    });

    tamperChain($this->org->id, "UPDATE audit_logs SET result = 'denied' WHERE organization_id = ':org' AND chain_seq = 3");

    $response = $this->client->send('POST', AUDIT_VERIFY)->assertOk();

    expect($response->json('data.valid'))->toBeFalse()
        ->and($response->json('data.first_broken_seq'))->toBe(3)
        ->and($response->json('data.reason_code'))->toBeString()
        ->and(array_keys($response->json('data')))->toBe(['valid', 'checked_count', 'first_broken_seq', 'reason_code'])
        ->and($logged)->toContain(['critical', 'audit.verification_failed']);

    $system = ownerDb()->table('audit_logs')->where('event_type', 'audit.verification_failed')->whereNull('organization_id')->sole();

    expect(json_decode((string) $system->metadata, true))->toMatchArray(['chain_id' => $this->org->id, 'first_broken_seq' => 3]);

    expect($this->client->send('GET', '/api/v1/audit-logs?limit=100')->assertOk()->getContent())->not->toContain('audit.verification_failed');
});

it('ST-28: a break in the system chain is nothing to this organization', function () {
    appendAudit(['metadata' => '{"n":1}']);
    tamperChain($this->org->id, "UPDATE audit_logs SET result = 'denied' WHERE organization_id IS NULL");

    $this->client->send('POST', AUDIT_VERIFY)->assertOk()->assertJsonPath('data.valid', true)->assertJsonPath('data.checked_count', 4);
});

it('ST-28: a break in another organization is nothing to this one', function () {
    $other = Organization::factory()->create();
    appendAudit(['organization' => $other->id, 'metadata' => '{"n":1}']);
    tamperChain($other->id, "UPDATE audit_logs SET result = 'denied' WHERE organization_id = ':org'");

    $this->client->send('POST', AUDIT_VERIFY)->assertOk()->assertJsonPath('data.valid', true);

    resetAuditTables();
    ownerDb()->table('organizations')->where('id', $other->id)->delete();
});

it('takes no chain from the request', function () {
    $this->client->send('POST', AUDIT_VERIFY, ['chain_id' => '00000000-0000-0000-0000-000000000000'])
        ->assertOk()->assertJsonPath('data.checked_count', 4);
});
