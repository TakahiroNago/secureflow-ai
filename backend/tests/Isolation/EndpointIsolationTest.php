<?php

use App\Domain\Workflow\AnalysisProcessor;
use App\Jobs\AnalyzeWorkflowJob;
use App\Models\AiAnalysisRequest;
use App\Models\Organization;
use App\Models\User;
use App\Support\Organization\OrganizationContext;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

/*
| ST-23: every endpoint that takes a resource, 2 organizations x 3 roles (docs/security-design.md §13.7).
| The list is checked against the route list, so a new endpoint fails here until it is added.
*/

uses(DatabaseTransactions::class);

const RESOURCE_ENDPOINTS = [
    ['GET', 'api/v1/analyses/{analysis}'],
    ['GET', 'api/v1/workflows/{workflow}'],
    ['GET', 'api/v1/workflows/{workflow}/history'],
    ['PATCH', 'api/v1/workflows/{workflow}'],
    ['POST', 'api/v1/workflows/{workflow}/tasks'],
    ['PUT', 'api/v1/workflows/{workflow}/tasks/{task}'],
    ['DELETE', 'api/v1/workflows/{workflow}/tasks/{task}'],
    ['POST', 'api/v1/workflows/{workflow}/submit'],
    ['POST', 'api/v1/workflows/{workflow}/reopen'],
    ['GET', 'api/v1/workflows/{workflow}/approval-context'],
    ['POST', 'api/v1/workflows/{workflow}/approve'],
    ['POST', 'api/v1/workflows/{workflow}/reject'],
    ['POST', 'api/v1/workflows/{workflow}/execute'],
    ['GET', 'api/v1/workflows/{workflow}/executions'],
    ['PATCH', 'api/v1/security/findings/{finding}'],
    ['GET', 'api/v1/security/scans/{scan}'],
];

const VALID_TASK = [
    'title' => 'T', 'description' => 'D', 'action_type' => 'text.analyze', 'steps' => ['S'],
    'priority' => 'low', 'target_data' => 'T', 'impact_summary' => 'I',
];

function fullOrganization(): array
{
    $org = Organization::factory()->create();
    $owner = userIn($org->id);

    $scan = insertScan(appDb(), $owner->organization_id, ['user_id' => $owner->id]);
    $finding = insertFinding(appDb(), $owner->organization_id, $scan);

    $analysis = app(OrganizationContext::class)->run($org->id, function () use ($owner, $scan) {
        $analysis = new AiAnalysisRequest;
        $analysis->forceFill(['user_id' => $owner->id, 'status' => 'queued', 'input_char_count' => 1, 'input_scan_id' => $scan])->save();

        return $analysis;
    });
    (new AnalyzeWorkflowJob($analysis->id, $org->id))->handle(app(AnalysisProcessor::class), app(OrganizationContext::class));
    $workflow = (string) DB::table('ai_analysis_requests')->where('id', $analysis->id)->value('workflow_id');

    return [
        'org' => $org,
        'owner' => $owner,
        'analysis' => $analysis->id,
        'workflow' => $workflow,
        'task' => (string) DB::table('workflow_tasks')->where('workflow_id', $workflow)->value('id'),
        'scan' => $scan,
        'finding' => $finding,
    ];
}

function requestFrom(TestCase $test, User $user, string $method, string $uri, array $target): TestResponse
{
    $path = '/'.strtr($uri, ['{analysis}' => $target['analysis'], '{workflow}' => $target['workflow'], '{task}' => $target['task'], '{scan}' => $target['scan'], '{finding}' => $target['finding']]);
    $body = in_array($method, ['PUT', 'POST'], true) ? VALID_TASK : ($method === 'PATCH' ? ['title' => 'x'] : null);

    return loggedIn($test, $user, ip: '203.0.113.'.random_int(30, 250))->send($method, $path, $body, ['HTTP_IF_MATCH' => '"1"']);
}

it('lists every endpoint that takes a resource', function () {
    $actual = [];

    /** @var RoutingRoute $route */
    foreach (Route::getRoutes()->getRoutes() as $route) {
        if (str_starts_with($route->uri(), 'api/v1/') && $route->parameterNames() !== []) {
            foreach (array_diff($route->methods(), ['HEAD']) as $method) {
                $actual[] = [$method, $route->uri()];
            }
        }
    }

    $sort = fn (array $list) => collect($list)->sortBy(fn ($item) => $item[0].$item[1])->values()->all();

    expect($sort($actual))->toBe($sort(RESOURCE_ENDPOINTS));
});

it('ST-23: answers 404 to every role of another organization, and changes nothing', function (string $method, string $uri, string $role) {
    $a = fullOrganization();
    $b = fullOrganization();
    $before = DB::table('workflows')->where('id', $a['workflow'])->first();
    $revisions = DB::table('workflow_revisions')->where('workflow_id', $a['workflow'])->count();
    $tasks = DB::table('workflow_tasks')->where('workflow_id', $a['workflow'])->count();

    $response = requestFrom($this, userIn($b['org']->id, $role), $method, $uri, $a);

    $response->assertStatus(404)->assertJsonPath('code', 'NOT_FOUND');

    expect(DB::table('workflows')->where('id', $a['workflow'])->first())->toEqual($before)
        ->and(DB::table('workflow_revisions')->where('workflow_id', $a['workflow'])->count())->toBe($revisions)
        ->and(DB::table('workflow_tasks')->where('workflow_id', $a['workflow'])->count())->toBe($tasks);
})->with(RESOURCE_ENDPOINTS)->with(['admin', 'member', 'auditor']);

it('ST-23: a task of another organization cannot be reached through one\'s own workflow', function (string $method) {
    $a = fullOrganization();
    $b = fullOrganization();

    $mixed = [...$b, 'task' => $a['task']];
    requestFrom($this, $b['owner'], $method, 'api/v1/workflows/{workflow}/tasks/{task}', $mixed)
        ->assertStatus(404);

    expect(DB::table('workflow_tasks')->where('id', $a['task'])->value('title'))->not->toBe('T');
})->with(['PUT', 'DELETE']);

it('the list shows nothing of another organization, whatever the role', function (string $role) {
    $a = fullOrganization();
    $b = fullOrganization();

    $response = loggedIn($this, userIn($b['org']->id, $role))->send('GET', '/api/v1/workflows')->assertOk();

    expect($response->getContent())->not->toContain($a['workflow']);
})->with(['admin', 'auditor', 'member']);

it('ST-34: the analysis and workflow routes have the rate limit or policy they should', function () {
    $analyses = Route::getRoutes()->getByName('analyses.store');

    expect($analyses->gatherMiddleware())->toContain('throttle:analyses')
        ->and(Route::getRoutes()->getByName('workflows.tasks.update')->gatherMiddleware())->toContain('can:update,workflow')
        ->and(Route::getRoutes()->getByName('workflows.tasks.update')->enforcesScopedBindings())->toBeTrue()
        ->and(Route::getRoutes()->getByName('workflows.tasks.destroy')->enforcesScopedBindings())->toBeTrue();
});
