<?php

namespace App\Domain\Settings;

use App\Audit\AuditAvailability;
use App\Audit\AuditEntry;
use App\Audit\AuditEventType;
use App\Audit\AuditLogger;
use App\Models\Organization;
use App\Models\OrganizationSetting;
use App\Models\User;
use App\Support\Database\SingleAttemptTransaction;
use App\Support\Http\ServiceUnavailableException;
use Illuminate\Support\Facades\DB;

/**
 * docs/api-design.md §3.9. The limits of an organization (docs/database-design.md §3.2). The organization's row is
 * locked so that two admins cannot both create the settings row, and the audit record is in the same transaction.
 * What did not change is not recorded: the chain says what the values became, not who looked.
 */
final readonly class OrganizationSettingsUpdater
{
    public function __construct(private AuditLogger $audit, private AuditAvailability $availability) {}

    /**
     * @param  array<string, int>  $changes  Only the fields that were sent.
     *
     * @throws ServiceUnavailableException when the audit record cannot be written
     */
    public function update(User $admin, array $changes): OrganizationSetting
    {
        $this->availability->assertAvailable();

        return SingleAttemptTransaction::run(DB::connection(), function () use ($admin, $changes): OrganizationSetting {
            Organization::query()->whereKey($admin->organization_id)->lockForUpdate()->firstOrFail();

            $settings = OrganizationSetting::query()->whereKey($admin->organization_id)->first()
                ?? (new OrganizationSetting)->forceFill(['organization_id' => $admin->organization_id, ...OrganizationSetting::DEFAULTS]);

            $changed = [];
            foreach (OrganizationSetting::LIMIT_FIELDS as $field) {
                if (array_key_exists($field, $changes) && $changes[$field] !== (int) $settings->getAttribute($field)) {
                    $settings->setAttribute($field, $changes[$field]);
                    $changed[$field] = $changes[$field];
                }
            }

            if ($changed === []) {
                return $settings;
            }

            $settings->forceFill(['updated_by' => $admin->id])->save();

            $this->audit->recordInTransaction(
                AuditEntry::byUserOn(AuditEventType::SettingsUpdated, $admin, 'organization_settings', $admin->organization_id, $changed),
                'settings_update_unrecorded',
            );

            return $settings;
        });
    }
}
