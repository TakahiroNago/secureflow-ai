<?php

use App\Models\Organization;
use App\Models\OrganizationSetting;
use Illuminate\Foundation\Testing\DatabaseTransactions;

/*
| ORG-CMD-01 (docs/test-strategy.md §36). The first organization of an environment where db:seed may not run
| (docs/database-design.md §4.5): the same rows as the seeder, and nothing a login could use.
*/

uses(DatabaseTransactions::class);

it('ORG-CMD-01: creates the organization with the default settings', function () {
    $this->artisan('organization:create', ['--name' => 'Acme'])->assertSuccessful();

    $organization = Organization::query()->where('name', 'Acme')->sole();
    $settings = OrganizationSetting::query()->whereKey($organization->id)->sole();

    expect($settings->only(OrganizationSetting::LIMIT_FIELDS))->toBe(OrganizationSetting::DEFAULTS)
        ->and($organization->users()->count())->toBe(0);
});

it('ORG-CMD-01: refuses a second organization with the same name, which user:create could not tell apart', function () {
    Organization::factory()->create(['name' => 'Acme']);

    $this->artisan('organization:create', ['--name' => 'Acme'])->assertFailed();

    expect(Organization::query()->where('name', 'Acme')->count())->toBe(1);
});

it('ORG-CMD-01: refuses a missing, too long or control-character name', function (?string $name) {
    $before = Organization::query()->count();

    $this->artisan('organization:create', $name === null ? [] : ['--name' => $name])->assertFailed();

    expect(Organization::query()->count())->toBe($before);
})->with([null, '', str_repeat('a', 101), "Acme\n"]);
