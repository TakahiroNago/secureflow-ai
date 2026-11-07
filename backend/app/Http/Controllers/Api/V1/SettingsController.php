<?php

namespace App\Http\Controllers\Api\V1;

use App\Ai\PromptBuilder;
use App\Domain\Settings\OrganizationSettingsUpdater;
use App\Http\Controllers\Controller;
use App\Http\Requests\UpdateLimitsRequest;
use App\Models\OrganizationSetting;
use App\Models\User;
use App\Security\Policy\ActionCatalog;
use App\Security\Scanning\Injection\InjectionScanner;
use App\Security\Scanning\InputScanner;
use App\Security\Scanning\ScanAction;
use App\Security\Scanning\Severity;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * docs/api-design.md §3.9. The provider, the model, the address and the key live in the environment (D5), and
 * this says only whether a key is there. The security settings are fixed in code (D4) and are read here, never set.
 */
final class SettingsController extends Controller
{
    public function ai(): JsonResponse
    {
        $model = config()->string('ai.openai.model');

        return response()->json(['data' => [
            'provider' => config()->string('ai.provider'),
            'model' => $model === '' ? null : $model,
            // True or false, and nothing of the key itself: not its length, not its last characters.
            'api_key_configured' => config()->string('ai.openai.api_key') !== '',
            'timeout_seconds' => config()->integer('ai.timeout_seconds'),
            'max_output_tokens' => config()->integer('ai.max_output_tokens'),
        ]]);
    }

    public function limits(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        return $this->limitsResponse($user->organization_id);
    }

    public function updateLimits(UpdateLimitsRequest $request, OrganizationSettingsUpdater $updater): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        $updater->update($user, $request->changes());

        return $this->limitsResponse($user->organization_id);
    }

    /**
     * What the code decides, as it is (docs/security-design.md §3.2, §9.3). Reading it from the classes that act on it
     * keeps this answer from drifting away from the behaviour.
     */
    public function security(InputScanner $scanner): JsonResponse
    {
        $injection = [];
        foreach (Severity::cases() as $severity) {
            $injection[$severity->value] = InjectionScanner::actionFor($severity)->value;
        }

        return response()->json(['data' => [
            'policy_version' => ActionCatalog::VERSION,
            'ruleset_version' => $scanner->rulesetVersion(),
            'prompt_version' => PromptBuilder::VERSION,
            'input_actions' => [
                'pii' => ScanAction::MaskContinue->value,
                'secret' => ScanAction::Block->value,
                'masking_failure' => ScanAction::Block->value,
                'injection' => $injection,
            ],
            'approval' => [
                'approver_role' => 'admin',
                'self_approval' => 'forbidden',
                'risk_acknowledgement_from' => Severity::Medium->value,
                'decisions_per_revision' => 1,
            ],
        ]]);
    }

    private function limitsResponse(string $organizationId): JsonResponse
    {
        $settings = OrganizationSetting::query()->with('updatedBy')->whereKey($organizationId)->first();
        $updatedBy = $settings?->updatedBy;

        return response()->json(['data' => [
            ...OrganizationSetting::effectiveFor($organizationId),
            'updated_at' => $settings?->updated_at?->toIso8601ZuluString(),
            'updated_by' => $updatedBy === null ? null : ['id' => $updatedBy->id, 'name' => $updatedBy->name],
        ]]);
    }
}
