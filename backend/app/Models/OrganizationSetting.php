<?php

namespace App\Models;

use Carbon\CarbonInterface;
use Database\Factories\OrganizationSettingFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * docs/database-design.md §3.2. An organization with no row still has limits: the defaults below, which are
 * also what the seeder writes.
 *
 * @property string $organization_id
 * @property int $monthly_token_limit
 * @property int $user_daily_request_limit
 * @property int $max_input_chars
 * @property string|null $updated_by
 * @property CarbonInterface|null $updated_at
 * @property-read User|null $updatedBy
 */
#[Fillable(['monthly_token_limit', 'user_daily_request_limit', 'max_input_chars'])]
class OrganizationSetting extends Model
{
    /** @use HasFactory<OrganizationSettingFactory> */
    use HasFactory;

    public const CREATED_AT = null;

    /** @var array{monthly_token_limit: int, user_daily_request_limit: int, max_input_chars: int} */
    public const DEFAULTS = [
        'monthly_token_limit' => 1_000_000,
        'user_daily_request_limit' => 100,
        'max_input_chars' => 4000,
    ];

    /** @var list<string> */
    public const LIMIT_FIELDS = ['monthly_token_limit', 'user_daily_request_limit', 'max_input_chars'];

    protected $primaryKey = 'organization_id';

    protected $keyType = 'string';

    public $incrementing = false;

    /**
     * The values in force for an organization, from its row or from the defaults.
     *
     * @return array{monthly_token_limit: int, user_daily_request_limit: int, max_input_chars: int}
     */
    public static function effectiveFor(string $organizationId): array
    {
        $settings = self::query()->whereKey($organizationId)->first();

        return [
            'monthly_token_limit' => $settings->monthly_token_limit ?? self::DEFAULTS['monthly_token_limit'],
            'user_daily_request_limit' => $settings->user_daily_request_limit ?? self::DEFAULTS['user_daily_request_limit'],
            'max_input_chars' => $settings->max_input_chars ?? self::DEFAULTS['max_input_chars'],
        ];
    }

    /**
     * @return BelongsTo<Organization, $this>
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    /**
     * @return BelongsTo<User, $this>
     */
    public function updatedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'updated_by');
    }
}
