<?php

namespace App\Console\Commands;

use App\Domain\Auth\PasswordPolicy;
use App\Models\Organization;
use App\Models\User;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;

/**
 * The only way to create a login user (docs/architecture.md D8, D18). The password is asked for
 * interactively and has no option, so it never reaches shell history or the process list.
 */
final class UserCreateCommand extends Command
{
    protected $signature = 'user:create
        {--organization= : Organization name or ID}
        {--name= : Display name}
        {--email= : Email address (login ID)}
        {--role=member : admin, member or auditor}';

    protected $description = 'Create a login user. The password is entered interactively.';

    public function handle(): int
    {
        $organization = $this->findOrganization();
        if ($organization === null) {
            return self::FAILURE;
        }

        $password = (string) $this->secret('Password');
        if ($password !== (string) $this->secret('Password (again)')) {
            $this->components->error('The passwords do not match.');

            return self::FAILURE;
        }

        $input = [
            'name' => $this->option('name'),
            'email' => $this->option('email'),
            'role' => $this->option('role'),
            'password' => $password,
        ];
        $validator = Validator::make($input, [
            'name' => ['required', 'string', 'max:100'],
            'email' => ['required', 'string', 'email:rfc', 'not_regex:/[[:cntrl:]]/', 'max:254', 'unique:users,email'],
            'role' => ['required', 'string', 'in:admin,member,auditor'],
            'password' => PasswordPolicy::rules(),
        ]);

        if ($validator->fails()) {
            foreach ($validator->errors()->all() as $message) {
                $this->components->error($message);
            }

            return self::FAILURE;
        }

        $user = new User;
        $user->forceFill([
            'organization_id' => $organization->id,
            'name' => $input['name'],
            'email' => $input['email'],
            'password' => $password,
            'role' => $input['role'],
            'password_changed_at' => now(),
        ])->save();

        $this->components->info("Created user {$user->id} ({$user->email}, {$user->role}).");

        return self::SUCCESS;
    }

    private function findOrganization(): ?Organization
    {
        $value = (string) $this->option('organization');

        $matches = Str::isUuid($value)
            ? Organization::query()->whereKey($value)->get()
            : Organization::query()->where('name', $value)->get();

        if ($matches->count() !== 1) {
            $this->components->error(
                $matches->isEmpty()
                    ? 'The organization was not found. Run the seeder or create it first.'
                    : 'Several organizations have this name. Use the ID.',
            );

            return null;
        }

        return $matches->first();
    }
}
