<?php

namespace App\Console\Commands;

use App\Models\Organization;
use App\Models\OrganizationSetting;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Validator;

/**
 * The first organization of an environment where the seeder may not run: db:seed is for development only
 * (docs/database-design.md §4.5). It writes the same rows as the seeder, the organization and its settings with
 * the defaults, and nothing else. Users come afterwards from user:create (docs/operations.md §4.2).
 */
final class OrganizationCreateCommand extends Command
{
    protected $signature = 'organization:create {--name= : The organization name (not in use yet)}';

    protected $description = 'Create an organization with its default settings.';

    public function handle(): int
    {
        $validator = Validator::make(['name' => $this->option('name')], [
            'name' => ['required', 'string', 'max:100', 'not_regex:/[[:cntrl:]]/'],
        ]);

        if ($validator->fails()) {
            foreach ($validator->errors()->all() as $message) {
                $this->components->error($message);
            }

            return self::FAILURE;
        }

        $name = (string) $validator->validated()['name'];

        // user:create finds an organization by name, so a name must stay unambiguous.
        if (Organization::query()->where('name', $name)->exists()) {
            $this->components->error('An organization with this name already exists.');

            return self::FAILURE;
        }

        // As the seeder: two inserts, no transaction of its own (AUDIT-CODE-01 reserves transactions for the audited
        // path). An organization without its settings row still has these limits (OrganizationSetting::effectiveFor).
        $organization = Organization::query()->create(['name' => $name]);
        $organization->settings()->create(OrganizationSetting::DEFAULTS);

        $this->components->info("Created organization {$organization->id} ({$organization->name}).");

        return self::SUCCESS;
    }
}
