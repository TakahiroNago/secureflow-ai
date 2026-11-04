<?php

namespace App\Models;

use Database\Factories\OrganizationSettingFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property string $organization_id
 * @property int $monthly_token_limit
 * @property int $user_daily_request_limit
 * @property int $max_input_chars
 */
#[Fillable(['monthly_token_limit', 'user_daily_request_limit', 'max_input_chars'])]
class OrganizationSetting extends Model
{
    /** @use HasFactory<OrganizationSettingFactory> */
    use HasFactory;

    public const CREATED_AT = null;

    protected $primaryKey = 'organization_id';

    protected $keyType = 'string';

    public $incrementing = false;

    /**
     * @return BelongsTo<Organization, $this>
     */
    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }
}
