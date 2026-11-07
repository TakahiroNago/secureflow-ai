<?php

use App\Http\Controllers\Api\V1\AccountPasswordController;
use App\Http\Controllers\Api\V1\AiUsageController;
use App\Http\Controllers\Api\V1\AnalysisController;
use App\Http\Controllers\Api\V1\ApprovalController;
use App\Http\Controllers\Api\V1\AuditLogController;
use App\Http\Controllers\Api\V1\AuthController;
use App\Http\Controllers\Api\V1\DashboardController;
use App\Http\Controllers\Api\V1\ExecutionController;
use App\Http\Controllers\Api\V1\SecurityController;
use App\Http\Controllers\Api\V1\SecurityFindingController;
use App\Http\Controllers\Api\V1\SecurityScanController;
use App\Http\Controllers\Api\V1\SettingsController;
use App\Http\Controllers\Api\V1\WorkflowController;
use App\Http\Controllers\Api\V1\WorkflowTaskController;
use App\Http\Controllers\HealthController;
use App\Models\AuditLog;
use App\Models\OrganizationSetting;
use App\Models\SecurityFinding;
use App\Models\Workflow;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful;

/*
| Health checks (no authentication). Rate limiting is applied by nginx, not by the
| application, so that readiness can still answer when Redis is unavailable.
| They skip the session middleware even when a browser calls them: sessions live in Redis, and
| liveness must not depend on it. See docs/api-design.md §3.10. The one allowed bypass (.semgrep/secureflow.yml).
*/
// nosemgrep: secureflow.php.middleware-bypass
Route::withoutMiddleware(EnsureFrontendRequestsAreStateful::class)->group(function (): void {
    Route::get('/health/live', [HealthController::class, 'live'])->name('health.live');
    Route::get('/health/ready', [HealthController::class, 'ready'])->name('health.ready');
});

/*
| Every route in this group except login needs a session. A test walks the route list, so a new
| route without authentication fails the suite (ST-05).
*/
Route::prefix('v1')->middleware('json.body')->group(function (): void {
    Route::post('/auth/login', [AuthController::class, 'login'])
        ->middleware(['frontend', 'throttle:login'])
        ->name('auth.login');

    Route::middleware(['db.available', 'auth:sanctum', 'session.current', 'org.context'])->group(function (): void {
        Route::post('/auth/logout', [AuthController::class, 'logout'])->name('auth.logout');
        Route::get('/auth/me', [AuthController::class, 'me'])->name('auth.me');

        // Everything else counts towards one limit. Logging out, and asking who one is, stay possible: the screen
        // would otherwise show someone over the limit as logged out.
        Route::middleware('throttle:api-general')->group(function (): void {
            Route::patch('/account/password', [AccountPasswordController::class, 'update'])
                ->middleware('throttle:account-password')
                ->name('account.password');

            Route::get('/dashboard/summary', [DashboardController::class, 'summary'])
                ->middleware('can:viewAny,'.Workflow::class)
                ->name('dashboard.summary');

            Route::get('/ai-usage/summary', [AiUsageController::class, 'summary'])
                ->middleware('can:viewAny,'.Workflow::class)
                ->name('ai-usage.summary');

            Route::post('/security/scan-preview', [SecurityController::class, 'scanPreview'])
                ->middleware(['throttle:scan-preview', 'can:create,'.Workflow::class])
                ->name('security.scan-preview');

            Route::post('/analyses', [AnalysisController::class, 'store'])
                ->middleware(['throttle:analyses', 'can:create,'.Workflow::class])
                ->name('analyses.store');
            Route::get('/analyses/{analysis}', [AnalysisController::class, 'show'])
                ->middleware('can:view,analysis')
                ->name('analyses.show');

            Route::get('/workflows', [WorkflowController::class, 'index'])
                ->middleware('can:viewAny,'.Workflow::class)
                ->name('workflows.index');
            Route::get('/workflows/{workflow}', [WorkflowController::class, 'show'])
                ->middleware('can:view,workflow')
                ->name('workflows.show');
            Route::get('/workflows/{workflow}/history', [WorkflowController::class, 'history'])
                ->middleware('can:view,workflow')
                ->name('workflows.history');
            Route::patch('/workflows/{workflow}', [WorkflowController::class, 'update'])
                ->middleware('can:update,workflow')
                ->name('workflows.update');

            Route::post('/workflows/{workflow}/submit', [WorkflowController::class, 'submit'])
                ->middleware('can:submit,workflow')
                ->name('workflows.submit');
            Route::post('/workflows/{workflow}/reopen', [WorkflowController::class, 'reopen'])
                ->middleware('can:reopen,workflow')
                ->name('workflows.reopen');

            Route::get('/approvals', [ApprovalController::class, 'index'])
                ->middleware('can:viewApprovals,'.Workflow::class)
                ->name('approvals.index');
            Route::get('/workflows/{workflow}/approval-context', [ApprovalController::class, 'context'])
                ->middleware('can:viewApprovalContext,workflow')
                ->name('workflows.approval-context');
            // The denial is recorded before the policy refuses, and after the limit: a refusal writes to the chain.
            Route::post('/workflows/{workflow}/approve', [ApprovalController::class, 'approve'])
                ->middleware(['throttle:approval-decisions', 'denied.attempt:approve', 'can:approve,workflow'])
                ->name('workflows.approve');
            Route::post('/workflows/{workflow}/reject', [ApprovalController::class, 'reject'])
                ->middleware(['throttle:approval-decisions', 'denied.attempt:reject', 'can:reject,workflow'])
                ->name('workflows.reject');

            Route::post('/workflows/{workflow}/execute', [ExecutionController::class, 'store'])
                ->middleware(['throttle:execution-requests', 'denied.attempt:execute', 'can:execute,workflow'])
                ->name('workflows.execute');
            Route::get('/workflows/{workflow}/executions', [ExecutionController::class, 'index'])
                ->middleware('can:view,workflow')
                ->name('workflows.executions');

            Route::get('/audit-logs', [AuditLogController::class, 'index'])
                ->middleware('can:viewAny,'.AuditLog::class)
                ->name('audit-logs.index');
            Route::post('/audit-logs/verify', [AuditLogController::class, 'verify'])
                ->middleware(['throttle:audit-verify', 'can:verify,'.AuditLog::class])
                ->name('audit-logs.verify');

            // docs/api-design.md §3.7. The route lets everyone in; the controller narrows a member's list to their own scans.
            Route::get('/security/findings', [SecurityFindingController::class, 'index'])
                ->middleware('can:viewAny,'.SecurityFinding::class)
                ->name('security.findings.index');
            Route::patch('/security/findings/{finding}', [SecurityFindingController::class, 'update'])
                ->middleware('can:update,finding')
                ->name('security.findings.update');
            Route::get('/security/scans/{scan}', [SecurityScanController::class, 'show'])
                ->middleware('can:view,scan')
                ->name('security.scans.show');

            // docs/api-design.md §3.9. Admin only. No answer holds the key, and the provider cannot be set from here.
            Route::get('/settings/ai', [SettingsController::class, 'ai'])
                ->middleware('can:view,'.OrganizationSetting::class)
                ->name('settings.ai');
            Route::get('/settings/limits', [SettingsController::class, 'limits'])
                ->middleware('can:view,'.OrganizationSetting::class)
                ->name('settings.limits');
            Route::patch('/settings/limits', [SettingsController::class, 'updateLimits'])
                ->middleware('can:update,'.OrganizationSetting::class)
                ->name('settings.limits.update');
            Route::get('/settings/security', [SettingsController::class, 'security'])
                ->middleware('can:view,'.OrganizationSetting::class)
                ->name('settings.security');

            Route::scopeBindings()->middleware('can:update,workflow')->group(function (): void {
                Route::post('/workflows/{workflow}/tasks', [WorkflowTaskController::class, 'store'])->name('workflows.tasks.store');
                Route::put('/workflows/{workflow}/tasks/{task}', [WorkflowTaskController::class, 'update'])->name('workflows.tasks.update');
                Route::delete('/workflows/{workflow}/tasks/{task}', [WorkflowTaskController::class, 'destroy'])->name('workflows.tasks.destroy');
            });
        });
    });
});
