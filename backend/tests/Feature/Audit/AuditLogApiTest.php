<?php

use App\Ai\AiFailure;
use App\Ai\AiGateway;
use App\Ai\AiProviderException;
use App\Ai\AiRequest;
use App\Ai\AiResponse;
use App\Ai\Contracts\AiProvider;
use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Audit\AuditWriter;
use App\Audit\RefusalRecorder;
use App\Domain\Workflow\AnalysisProcessor;
use App\Jobs\AnalyzeWorkflowJob;
use App\Models\AiAnalysisRequest;
use App\Models\AuditLog;
use App\Models\Organization;
use App\Models\User;
use App\Support\Organization\MissingOrganizationContextException;
use App\Support\Organization\OrganizationContext;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use Tests\Support\FailingAuditWriter;

/*
| docs/api-design.md §3.8, docs/security-design.md §16.1, §16.7. ST-06 and AUDIT-SYS-01 over HTTP, and the events that
| arrive in step 2-7. The verification reads committed rows, so ST-28 is in AuditLogVerifyApiTest.
*/

uses(DatabaseTransactions::class);

const AUDIT_LOGS = '/api/v1/audit-logs';

const SOME_WORKFLOW = '/api/v1/workflows/019a0000-0000-7000-8000-00000000000a';

function auditRows(string $type, string $organizationId): array
{
    return DB::table('audit_logs')->where('event_type', $type)->where('organization_id', $organizationId)->orderBy('chain_seq')->get()->all();
}

function auditRecord(string $organizationId, array $overrides = []): void
{
    appendAudit(['organization' => $organizationId, ...$overrides]);
}

beforeEach(function () {
    $this->org = Organization::factory()->create();
    $this->admin = userIn($this->org->id, 'admin');
    $this->auditor = userIn($this->org->id, 'auditor');
    $this->member = userIn($this->org->id);
});

// ---- Who can read -----------------------------------------------------------------------------------

it('ST-06: an admin and an auditor read the log, and a member does not', function (string $role, int $status) {
    $user = match ($role) {
        'admin' => $this->admin,
        'auditor' => $this->auditor,
        'member' => $this->member,
    };

    loggedIn($this, $user)->send('GET', AUDIT_LOGS)->assertStatus($status);
    loggedIn($this, $user)->send('POST', AUDIT_LOGS.'/verify')->assertStatus($status);
})->with([['admin', 200], ['auditor', 200], ['member', 403]])->group('security');

it('ST-06: a deactivated user is refused by the policy too', function (string $role) {
    $user = userIn($this->org->id, $role, ['is_active' => false]);

    expect(Gate::forUser($user)->denies('viewAny', AuditLog::class))->toBeTrue()
        ->and(Gate::forUser($user)->denies('verify', AuditLog::class))->toBeTrue();
})->with(['admin', 'auditor'])->group('security');

it('has no way to change the log', function (string $method) {
    loggedIn($this, $this->admin)->send($method, AUDIT_LOGS, $method === 'DELETE' ? null : [])->assertStatus(405);
})->with(['POST', 'PUT', 'PATCH', 'DELETE']);

it('refuses to write through the model', function () {
    app(OrganizationContext::class)->run($this->org->id, function () {
        expect(fn () => (new AuditLog)->forceFill(['event_type' => 'test.event'])->save())->toThrow(LogicException::class);
    });
});

it('does not read without an organization', function () {
    expect(fn () => AuditLog::query()->count())->toThrow(MissingOrganizationContextException::class);
});

// ---- What it shows ---------------------------------------------------------------------------------------

it('returns what is designed, in chain order, and nothing about the hashes', function () {
    $client = loggedIn($this, $this->admin);

    $response = $client->send('GET', AUDIT_LOGS)->assertOk();
    $row = $response->json('data.0');

    expect(array_keys($row))->toEqualCanonicalizing(['event_id', 'chain_seq', 'event_type', 'result', 'severity', 'actor', 'resource', 'ip_address', 'request_id', 'metadata', 'occurred_at'])
        ->and($row['event_type'])->toBe('auth.login')
        ->and($row['actor'])->toMatchArray(['type' => 'user', 'id' => $this->admin->id, 'name' => $this->admin->name])
        ->and($row['ip_address'])->toBe('203.0.113.10')
        ->and($response->getContent())->not->toContain('prev_hash')
        ->and($response->getContent())->not->toContain('chain_id');
});

it('goes newest first by chain_seq, whatever the clock said, and pages through', function () {
    foreach (range(1, 3) as $n) {
        auditRecord($this->org->id, ['type' => 'workflow.updated', 'metadata' => '{"n":'.$n.'}']);
    }
    $client = loggedIn($this, $this->auditor);

    $first = $client->send('GET', AUDIT_LOGS.'?limit=2&event_type=workflow.updated')->assertOk();
    $next = $first->json('meta.next_cursor');
    $rest = $client->send('GET', AUDIT_LOGS.'?limit=2&event_type=workflow.updated&cursor='.urlencode((string) $next))->assertOk();
    $seqs = [...array_column($first->json('data'), 'chain_seq'), ...array_column($rest->json('data'), 'chain_seq')];

    expect($seqs)->toHaveCount(3);

    $sorted = $seqs;
    rsort($sorted);

    expect($seqs)->toBe($sorted)->and($rest->json('meta.next_cursor'))->toBeNull();
});

it('filters', function (string $query, int $expected) {
    auditRecord($this->org->id, ['type' => 'workflow.updated']);
    auditRecord($this->org->id, ['type' => 'workflow.created', 'result' => 'denied', 'severity' => 'high']);
    $client = loggedIn($this, $this->auditor);

    $response = $client->send('GET', AUDIT_LOGS.'?'.$query)->assertOk();

    expect($response->json('data'))->toHaveCount($expected);
})->with([
    ['event_type=workflow.updated', 1],
    ['result=denied', 1],
    ['severity=high', 1],
    ['from=2000-01-01T00:00:00Z&event_type=workflow.created', 1],
    ['to=2000-01-01T00:00:00Z', 0],
    ['from=2999-01-01T00:00:00Z', 0],
]);

it('filters by who did it', function () {
    $client = loggedIn($this, $this->auditor);
    loggedIn($this, $this->admin);

    $response = $client->send('GET', AUDIT_LOGS.'?actor_user_id='.$this->admin->id)->assertOk();

    expect(array_unique(array_column(array_column($response->json('data'), 'actor'), 'id')))->toBe([$this->admin->id]);
});

it('refuses what it does not know, including a chain', function (string $query, string $field) {
    loggedIn($this, $this->admin)->send('GET', AUDIT_LOGS.'?'.$query)->assertStatus(422)->assertJsonValidationErrors([$field]);
})->with([
    ['event_type=made.up', 'event_type'],
    ['actor_user_id=1', 'actor_user_id'],
    ['result=maybe', 'result'],
    ['severity=none', 'severity'],
    ['from=yesterdayish', 'from'],
    ['limit=101', 'limit'],
    ['chain_id=00000000-0000-0000-0000-000000000000', 'chain_id'],
    ['organization_id=x', 'organization_id'],
]);

// ---- AUDIT-SYS-01 and the other organization ------------------------------------------------------------

it('AUDIT-SYS-01: the system chain is never in the answer', function () {
    $marker = (string) Str::uuid7();
    appendAudit(['event' => $marker, 'type' => 'auth.login_failed', 'actor_type' => 'anonymous', 'result' => 'failure']);
    $client = loggedIn($this, $this->admin);

    foreach (['', '?event_type=auth.login_failed', '?result=failure', '?limit=100'] as $query) {
        expect($client->send('GET', AUDIT_LOGS.$query)->assertOk()->getContent())->not->toContain($marker);
    }
});

it('never shows another organization', function () {
    $other = Organization::factory()->create();
    $marker = (string) Str::uuid7();
    auditRecord($other->id, ['event' => $marker]);
    $otherUser = userIn($other->id, 'admin');

    $response = loggedIn($this, $this->admin)->send('GET', AUDIT_LOGS.'?limit=100&actor_user_id='.$otherUser->id)->assertOk();

    expect($response->json('data'))->toBe([])
        ->and(loggedIn($this, $this->admin)->send('GET', AUDIT_LOGS.'?limit=100')->getContent())->not->toContain($marker);
});

// ---- authz.denied ---------------------------------------------------------------------------------------------

it('records a 403 and a 404, by route and status only', function () {
    $client = loggedIn($this, $this->member);

    $client->send('GET', AUDIT_LOGS)->assertStatus(403);
    $client->send('GET', SOME_WORKFLOW)->assertStatus(404);

    $rows = auditRows('authz.denied', $this->org->id);
    $meta = array_map(fn ($row) => json_decode((string) $row->metadata, true), $rows);

    expect($meta)->toHaveCount(2)
        ->and($meta[0])->toEqual(['route' => 'audit-logs.index', 'status' => 403])
        ->and($meta[1])->toEqual(['route' => 'workflows.show', 'status' => 404])
        ->and($rows[0]->actor_user_id)->toBe($this->member->id)
        ->and($rows[1]->resource_id)->toBeNull()
        ->and($rows[0]->result)->toBe('denied')
        ->and(json_encode($rows))->not->toContain('019a0000-0000-7000-8000-00000000000a');
});

it('writes one record a minute for the same user, route and status, and again in the next', function () {
    $client = loggedIn($this, $this->member);

    foreach (range(1, 5) as $ignored) {
        $client->send('GET', SOME_WORKFLOW)->assertStatus(404);
    }
    $client->send('GET', AUDIT_LOGS)->assertStatus(403);
    loggedIn($this, $this->auditor)->send('GET', SOME_WORKFLOW)->assertStatus(404);

    expect(auditRows('authz.denied', $this->org->id))->toHaveCount(3);

    $this->travel(61)->seconds();
    $client = loggedIn($this, $this->member);
    $client->send('GET', SOME_WORKFLOW)->assertStatus(404);

    expect(auditRows('authz.denied', $this->org->id))->toHaveCount(4);
});

it('counts each route and each status on its own', function () {
    $workflow = app(OrganizationContext::class)->run($this->org->id, fn () => workflowOf($this->member));
    $client = loggedIn($this, $this->auditor);

    // Two routes with the same status, then one route with two statuses.
    $client->send('GET', SOME_WORKFLOW)->assertStatus(404);
    $client->send('GET', SOME_WORKFLOW.'/history')->assertStatus(404);
    $client->send('PATCH', '/api/v1/workflows/'.$workflow->id, ['title' => 'x'])->assertStatus(403);
    $client->send('PATCH', SOME_WORKFLOW, ['title' => 'x'])->assertStatus(404);

    $seen = array_map(fn ($row) => json_decode((string) $row->metadata, true), auditRows('authz.denied', $this->org->id));

    expect($seen)->toEqualCanonicalizing([
        ['route' => 'workflows.show', 'status' => 404],
        ['route' => 'workflows.history', 'status' => 404],
        ['route' => 'workflows.update', 'status' => 403],
        ['route' => 'workflows.update', 'status' => 404],
    ]);
});

it('looks at nothing for an error that is not a refusal', function () {
    $availability = Mockery::mock(AuditAvailability::class);
    $availability->shouldNotReceive('dbFlagged');
    $request = Request::create('/api/v1/audit-logs');
    $request->setRouteResolver(fn () => (new Route('GET', 'api/v1/audit-logs', fn () => null))->name('audit-logs.index'));

    (new RefusalRecorder(app(AuditLogger::class), $availability))->note(new RuntimeException('no'), $request);
});

it('does not record twice where a refusal has its own record', function () {
    $own = app(OrganizationContext::class)->run($this->org->id, fn () => workflowOf($this->auditor));
    $client = loggedIn($this, $this->member);
    $auditorClient = loggedIn($this, $this->auditor);

    $auditorClient->send('POST', '/api/v1/workflows/'.$own->id.'/execute', null, ['HTTP_IDEMPOTENCY_KEY' => 'k'])->assertStatus(403);

    expect(auditRows('execution.denied', $this->org->id))->toHaveCount(1)
        ->and(auditRows('authz.denied', $this->org->id))->toHaveCount(0);

    // Nothing is said about a workflow this person may not know of, except that they asked.
    $client->send('POST', '/api/v1/workflows/'.$own->id.'/execute', null, ['HTTP_IDEMPOTENCY_KEY' => 'k'])->assertStatus(404);

    expect(auditRows('execution.denied', $this->org->id))->toHaveCount(1)
        ->and(auditRows('authz.denied', $this->org->id))->toHaveCount(1);
});

it('records nothing for a path that is no route, or for someone not logged in', function () {
    $before = DB::table('audit_logs')->count();

    spa($this)->send('GET', AUDIT_LOGS)->assertStatus(401);
    spa($this)->send('GET', '/api/v1/no-such-thing')->assertStatus(404);

    expect(DB::table('audit_logs')->count())->toBe($before);
});

it('does not touch the database for a refusal while it is known to be unavailable', function () {
    $client = spa($this);
    $client->csrf();
    Cache::put('audit:db_unavailable', ['started_at' => now()->getTimestamp()], 60);
    $before = DB::table('audit_logs')->count();

    foreach (range(1, 7) as $ignored) {
        $last = $client->send('POST', '/api/v1/auth/login', ['email' => 'limited@example.com', 'password' => 'wrong password here']);
    }
    $last->assertStatus(429);

    Cache::forget('audit:db_unavailable');

    expect(DB::table('audit_logs')->count())->toBe($before);
});

it('changes no answer when the record cannot be written', function () {
    $client = loggedIn($this, $this->member);
    useAuditWriter(new FailingAuditWriter('53100', 'could not extend file: No space left on device'));

    $client->send('GET', AUDIT_LOGS)->assertStatus(403)->assertJsonPath('code', 'FORBIDDEN');
    $client->send('GET', SOME_WORKFLOW)->assertStatus(404)->assertJsonPath('code', 'NOT_FOUND');
});

// ---- rate_limit.exceeded --------------------------------------------------------------------------------------

it('records the limit of a logged-in user once a minute, on their own chain', function () {
    $client = loggedIn($this, $this->member);

    foreach (range(1, 12) as $ignored) {
        $last = $client->send('POST', '/api/v1/security/scan-preview', ['input' => 'x']);
    }
    $last->assertStatus(429);

    $rows = auditRows('rate_limit.exceeded', $this->org->id);

    expect($rows)->toHaveCount(1)
        ->and($rows[0]->actor_user_id)->toBe($this->member->id)
        ->and(json_decode((string) $rows[0]->metadata, true))->toEqual(['route' => 'security.scan-preview']);
});

it('records a limited login anonymously on the system chain, and no email address in any form', function () {
    $email = 'nobody-'.bin2hex(random_bytes(4)).'@example.com';
    $client = spa($this);
    $client->csrf();
    $before = DB::table('audit_logs')->where('event_type', 'rate_limit.exceeded')->whereNull('organization_id')->count();

    foreach (range(1, 7) as $ignored) {
        $last = $client->send('POST', '/api/v1/auth/login', ['email' => $email, 'password' => 'wrong password here']);
    }
    $last->assertStatus(429);

    $rows = DB::table('audit_logs')->where('event_type', 'rate_limit.exceeded')->whereNull('organization_id')->orderBy('chain_seq')->get();

    expect($rows->count())->toBe($before + 1)
        ->and($rows->last()->actor_type)->toBe('anonymous')
        ->and(json_decode((string) $rows->last()->metadata, true))->toEqual(['route' => 'auth.login'])
        ->and(json_encode($rows))->not->toContain($email)
        ->and(json_encode($rows))->not->toContain(hash('sha256', $email));
});

it('limits verification by organization, and lets no member use it up', function () {
    $member = loggedIn($this, $this->member);

    foreach (range(1, 5) as $ignored) {
        $member->send('POST', AUDIT_LOGS.'/verify')->assertStatus(403);
    }

    $admin = loggedIn($this, $this->admin);
    $auditor = loggedIn($this, $this->auditor);

    $admin->send('POST', AUDIT_LOGS.'/verify')->assertOk();
    $auditor->send('POST', AUDIT_LOGS.'/verify')->assertOk();
    $admin->send('POST', AUDIT_LOGS.'/verify')->assertOk();
    $auditor->send('POST', AUDIT_LOGS.'/verify')->assertStatus(429);

    $other = Organization::factory()->create();
    loggedIn($this, userIn($other->id, 'admin'))->send('POST', AUDIT_LOGS.'/verify')->assertOk();
});

// ---- ai.call ----------------------------------------------------------------------------------------------------

function analyzeAs(User $user): string
{
    $analysis = app(OrganizationContext::class)->run($user->organization_id, function () use ($user) {
        $analysis = new AiAnalysisRequest;
        $analysis->forceFill(['user_id' => $user->id, 'status' => 'queued', 'input_masked' => '週次の報告', 'input_char_count' => 1, 'input_scan_id' => insertScan(appDb(), $user->organization_id)])->save();

        return $analysis;
    });
    (new AnalyzeWorkflowJob($analysis->id, $analysis->organization_id))->handle(app(AnalysisProcessor::class), app(OrganizationContext::class));

    return $analysis->id;
}

it('records an AI call, with no text', function () {
    $analysis = analyzeAs($this->member);

    $row = auditRows('ai.call', $this->org->id)[0];

    expect($row->actor_user_id)->toBe($this->member->id)
        ->and($row->result)->toBe('success')
        ->and($row->resource_id)->toBe($analysis)
        ->and(json_decode((string) $row->metadata, true))->toEqual(['provider' => 'mock'])
        ->and((string) $row->metadata)->not->toContain('週次');
});

it('records an AI call that failed, with its kind and no text', function () {
    app()->bind(AiProvider::class, fn () => new class implements AiProvider
    {
        public function generate(AiRequest $request): AiResponse
        {
            throw new AiProviderException(AiFailure::Rejected);
        }
    });
    app()->forgetInstance(AiGateway::class);

    analyzeAs($this->member);

    $row = auditRows('ai.call', $this->org->id)[0];

    expect($row->result)->toBe('failure')
        ->and(json_decode((string) $row->metadata, true))->toEqual(['provider' => 'mock', 'reason_code' => 'rejected']);
});

it('does not stop an analysis when the call cannot be recorded', function () {
    useAuditWriter(new class extends AuditWriter
    {
        public function __construct() {}

        public function append(AuditEntry $entry, ?string $ip, ?string $requestId): int
        {
            if ($entry->type === AuditEventType::AiCall) {
                throw new RuntimeException('no');
            }

            return app(AuditWriter::class)::class === '' ? 0 : 1;
        }
    });

    $analysis = analyzeAs($this->member);

    expect(DB::table('ai_analysis_requests')->where('id', $analysis)->value('status'))->not->toBe('queued')
        ->and(auditRows('ai.call', $this->org->id))->toHaveCount(0);
});
