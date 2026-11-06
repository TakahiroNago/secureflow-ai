<?php

use App\Http\Middleware\SetOrganizationContext;
use App\Models\Workflow;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Route;

/*
| ST-34: no route can be added without authentication, an organization context and a policy. It walks
| the route list, so a new route is covered the moment it exists.
*/

/** Their subject is the user who is logged in, so there is no resource to authorize. */
const ROUTES_ABOUT_THE_CURRENT_USER = ['api/v1/auth/logout', 'api/v1/auth/me', 'api/v1/account/password'];

const ROUTES_WITHOUT_A_SESSION = ['api/v1/auth/login'];

/**
 * @return list<string> what is missing, by route
 */
function missingAuthorization(): array
{
    $missing = [];

    /** @var RoutingRoute $route */
    foreach (Route::getRoutes()->getRoutes() as $route) {
        if (! str_starts_with($route->uri(), 'api/v1/') || in_array($route->uri(), ROUTES_WITHOUT_A_SESSION, true)) {
            continue;
        }

        $middleware = $route->gatherMiddleware();

        foreach (['auth:sanctum', 'session.current', 'org.context'] as $required) {
            if (! in_array($required, $middleware, true)) {
                $missing[] = "{$route->uri()}: {$required}";
            }
        }

        $hasPolicy = collect($middleware)->contains(fn ($name) => is_string($name) && str_starts_with($name, 'can:'));

        if (! $hasPolicy && ! in_array($route->uri(), ROUTES_ABOUT_THE_CURRENT_USER, true)) {
            $missing[] = "{$route->uri()}: can:";
        }
    }

    return $missing;
}

it('ST-34: every API route has authentication, an organization and a policy', function () {
    expect(missingAuthorization())->toBe([]);
});

it('ST-34: notices a route with no policy', function () {
    Route::middleware(['auth:sanctum', 'session.current', 'org.context'])->get('/api/v1/forgot-policy', fn () => null);

    expect(missingAuthorization())->toBe(['api/v1/forgot-policy: can:']);
});

it('ST-34: notices a route with no authentication or organization', function () {
    Route::middleware(['can:viewAny,'.Workflow::class])->get('/api/v1/forgot-auth', fn () => null);

    expect(missingAuthorization())->toBe([
        'api/v1/forgot-auth: auth:sanctum',
        'api/v1/forgot-auth: session.current',
        'api/v1/forgot-auth: org.context',
    ]);
});

it('ST-34: accepts a route that has all of them', function () {
    Route::middleware(['auth:sanctum', 'session.current', 'org.context', 'can:viewAny,'.Workflow::class])->get('/api/v1/complete', fn () => null);

    expect(missingAuthorization())->toBe([]);
});

it('resolves route model binding inside the organization scope', function () {
    Route::middleware(['api', 'auth:sanctum', 'org.context'])->get('/api/v1/order/{workflow}', fn (Workflow $workflow) => null);

    $route = Route::getRoutes()->match(Request::create('/api/v1/order/x'));
    $order = app('router')->gatherRouteMiddleware($route);

    $position = fn (string $class) => array_search($class, $order, true);

    expect($position(SetOrganizationContext::class))
        ->toBeLessThan($position(SubstituteBindings::class));
});
