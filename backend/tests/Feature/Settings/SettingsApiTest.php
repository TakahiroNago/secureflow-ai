<?php

use App\Ai\PromptBuilder;
use App\Domain\Workflow\AiUsageLedger;
use App\Models\Organization;
use App\Security\Policy\ActionCatalog;
use App\Security\Scanning\InputScanner;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Tests\Support\FailingAuditWriter;

/*
| docs/api-design.md §3.9, docs/security-design.md §18. ST-06 over the settings, the key that never leaves the server,
| the limits with their audit record, and the security policy as the code has it.
*/

uses(DatabaseTransactions::class);

const SETTINGS_AI_URI = '/api/v1/settings/ai';

const SETTINGS_LIMITS_URI = '/api/v1/settings/limits';

const SETTINGS_SECURITY_URI = '/api/v1/settings/security';

const FAKE_KEY = 'sk-proj-ThisIsNotARealKey0123456789abcdefABCDEF';

function settingsEvents(string $organizationId): array
{
    return DB::table('audit_logs')->where('organization_id', $organizationId)->where('event_type', 'settings.updated')->orderBy('chain_seq')->get()->all();
}

function settingsRow(string $organizationId): ?object
{
    return DB::table('organization_settings')->where('organization_id', $organizationId)->first();
}

beforeEach(function () {
    $this->org = Organization::factory()->create();
    $this->admin = userIn($this->org->id, 'admin');
    $this->auditor = userIn($this->org->id, 'auditor');
    $this->member = userIn($this->org->id);
});

it('ST-06: only an admin reads or changes the settings', function (string $role, int $status) {
    $user = match ($role) {
        'admin' => $this->admin,
        'auditor' => $this->auditor,
        'member' => $this->member,
    };
    $client = loggedIn($this, $user);

    $client->send('GET', SETTINGS_AI_URI)->assertStatus($status);
    $client->send('GET', SETTINGS_LIMITS_URI)->assertStatus($status);
    $client->send('PATCH', SETTINGS_LIMITS_URI, ['max_input_chars' => 100])->assertStatus($status);
    $client->send('GET', SETTINGS_SECURITY_URI)->assertStatus($status);

    if ($status !== 200) {
        expect(settingsRow($this->org->id))->toBeNull()
            ->and(settingsEvents($this->org->id))->toBe([]);
    }
})->with([['admin', 200], ['auditor', 403], ['member', 403]]);

it('has no way to change the AI or the security settings', function (string $uri) {
    loggedIn($this, $this->admin)->send('PATCH', $uri, [])->assertStatus(405);
})->with([SETTINGS_AI_URI, SETTINGS_SECURITY_URI]);

// ---- AI --------------------------------------------------------------------------------------------------

it('says whether a key is configured, and never what it is', function () {
    config(['ai.openai.api_key' => FAKE_KEY, 'ai.openai.model' => 'gpt-6-luna']);

    $response = loggedIn($this, $this->admin)->send('GET', SETTINGS_AI_URI)->assertOk();

    expect(array_keys($response->json('data')))->toBe(['provider', 'model', 'api_key_configured', 'timeout_seconds', 'max_output_tokens'])
        ->and($response->json('data'))->toMatchArray(['provider' => 'mock', 'model' => 'gpt-6-luna', 'api_key_configured' => true, 'timeout_seconds' => 30, 'max_output_tokens' => 2000])
        ->and($response->getContent())->not->toContain(FAKE_KEY)
        ->and($response->getContent())->not->toContain(substr(FAKE_KEY, -4));
});

it('says when there is no key and no model', function () {
    config(['ai.openai.api_key' => '', 'ai.openai.model' => '']);

    loggedIn($this, $this->admin)->send('GET', SETTINGS_AI_URI)->assertOk()
        ->assertJsonPath('data.api_key_configured', false)
        ->assertJsonPath('data.model', null);
});

// ---- Limits ------------------------------------------------------------------------------------------------

it('returns the defaults for an organization with no settings row', function () {
    loggedIn($this, $this->admin)->send('GET', SETTINGS_LIMITS_URI)->assertOk()
        ->assertExactJson(['data' => ['monthly_token_limit' => 1_000_000, 'user_daily_request_limit' => 100, 'max_input_chars' => 4000, 'updated_at' => null, 'updated_by' => null]]);
});

it('changes limits, records what changed, and the limits are in force at once', function () {
    $client = loggedIn($this, $this->admin);

    $response = $client->send('PATCH', SETTINGS_LIMITS_URI, ['user_daily_request_limit' => 1, 'max_input_chars' => 10])->assertOk();

    expect($response->json('data'))->toMatchArray(['monthly_token_limit' => 1_000_000, 'user_daily_request_limit' => 1, 'max_input_chars' => 10])
        ->and($response->json('data.updated_by'))->toBe(['id' => $this->admin->id, 'name' => $this->admin->name])
        ->and($response->json('data.updated_at'))->not->toBeNull();

    $row = settingsRow($this->org->id);
    expect($row->monthly_token_limit)->toBe(1_000_000)
        ->and($row->user_daily_request_limit)->toBe(1)
        ->and($row->max_input_chars)->toBe(10)
        ->and($row->updated_by)->toBe($this->admin->id);

    $events = settingsEvents($this->org->id);
    expect($events)->toHaveCount(1)
        ->and($events[0]->actor_user_id)->toBe($this->admin->id)
        ->and($events[0]->resource_type)->toBe('organization_settings')
        ->and($events[0]->resource_id)->toBe($this->org->id)
        ->and(json_decode($events[0]->metadata, true))->toEqualCanonicalizing(['user_daily_request_limit' => 1, 'max_input_chars' => 10]);

    // The same request reads the row again: nothing is cached.
    expect($client->send('GET', SETTINGS_LIMITS_URI)->assertOk()->json('data.max_input_chars'))->toBe(10)
        ->and(app(AiUsageLedger::class)->limitsOf($this->org->id))->toBe(['monthly_tokens' => 1_000_000, 'daily_requests' => 1]);

    loggedIn($this, $this->member)->send('POST', '/api/v1/security/scan-preview', ['input' => str_repeat('あ', 11)])
        ->assertStatus(422)->assertJsonValidationErrors(['input']);
    loggedIn($this, $this->member)->send('POST', '/api/v1/security/scan-preview', ['input' => str_repeat('あ', 10)])
        ->assertOk();
});

it('records only what changed, and nothing when nothing changed', function () {
    insertSettings(appDb(), $this->org->id, ['monthly_token_limit' => 1000, 'user_daily_request_limit' => 10]);
    $client = loggedIn($this, $this->admin);

    $client->send('PATCH', SETTINGS_LIMITS_URI, ['monthly_token_limit' => 1000])->assertOk();
    expect(settingsEvents($this->org->id))->toBe([])
        ->and(settingsRow($this->org->id)->updated_by)->toBeNull();

    $client->send('PATCH', SETTINGS_LIMITS_URI, ['monthly_token_limit' => 2000, 'user_daily_request_limit' => 10])->assertOk()
        ->assertJsonPath('data.monthly_token_limit', 2000);
    $events = settingsEvents($this->org->id);
    expect($events)->toHaveCount(1)
        ->and(json_decode($events[0]->metadata, true))->toBe(['monthly_token_limit' => 2000])
        ->and(settingsRow($this->org->id)->updated_by)->toBe($this->admin->id);
});

it('takes whole numbers in range, as numbers', function (array $body, string $field) {
    loggedIn($this, $this->admin)->send('PATCH', SETTINGS_LIMITS_URI, $body)
        ->assertStatus(422)->assertJsonPath('code', 'VALIDATION_FAILED')->assertJsonValidationErrors([$field]);

    expect(settingsRow($this->org->id))->toBeNull()
        ->and(settingsEvents($this->org->id))->toBe([]);
})->with([
    'a number as a string' => [['max_input_chars' => '100'], 'max_input_chars'],
    'zero' => [['user_daily_request_limit' => 0], 'user_daily_request_limit'],
    'a fraction' => [['user_daily_request_limit' => 1.5], 'user_daily_request_limit'],
    'too many tokens' => [['monthly_token_limit' => 1_000_000_001], 'monthly_token_limit'],
    'too many requests' => [['user_daily_request_limit' => 100_001], 'user_daily_request_limit'],
    'too long an input' => [['max_input_chars' => 20_001], 'max_input_chars'],
    'nothing' => [[], 'monthly_token_limit'],
    'an unknown field' => [['max_input_chars' => 100, 'organization_id' => 'x'], 'organization_id'],
]);

it('answers 503 and keeps the old limits when the record cannot be written', function () {
    $client = loggedIn($this, $this->admin);
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));

    $client->send('PATCH', SETTINGS_LIMITS_URI, ['max_input_chars' => 10])
        ->assertStatus(503)->assertJsonPath('code', 'SERVICE_UNAVAILABLE');

    expect(settingsRow($this->org->id))->toBeNull()
        ->and(app(AiUsageLedger::class)->limitsOf($this->org->id)['daily_requests'])->toBe(100);
});

it('changes only its own organization', function () {
    $otherOrg = Organization::factory()->create();
    $otherAdmin = userIn($otherOrg->id, 'admin');

    loggedIn($this, $otherAdmin)->send('PATCH', SETTINGS_LIMITS_URI, ['max_input_chars' => 50])->assertOk();

    expect(settingsRow($this->org->id))->toBeNull()
        ->and(settingsRow($otherOrg->id)->max_input_chars)->toBe(50)
        ->and(loggedIn($this, $this->admin)->send('GET', SETTINGS_LIMITS_URI)->json('data.max_input_chars'))->toBe(4000);
});

// ---- Security ----------------------------------------------------------------------------------------------

it('describes the security policy as the code has it', function () {
    $response = loggedIn($this, $this->admin)->send('GET', SETTINGS_SECURITY_URI)->assertOk();

    expect($response->json('data'))->toBe([
        'policy_version' => ActionCatalog::VERSION,
        'ruleset_version' => app(InputScanner::class)->rulesetVersion(),
        'prompt_version' => PromptBuilder::VERSION,
        'input_actions' => [
            'pii' => 'mask_continue',
            'secret' => 'block',
            'masking_failure' => 'block',
            'injection' => ['low' => 'record', 'medium' => 'warn', 'high' => 'block', 'critical' => 'block'],
        ],
        'approval' => ['approver_role' => 'admin', 'self_approval' => 'forbidden', 'risk_acknowledgement_from' => 'medium', 'decisions_per_revision' => 1],
    ])
        ->and($response->json('data.ruleset_version'))->toMatch('/^\d{4}\.\d+\.\d+\/\S+$/');
});
