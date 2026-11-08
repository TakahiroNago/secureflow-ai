<?php

namespace App\Console\Commands;

use App\Ai\Evaluation\AiEvaluator;
use App\Ai\Evaluation\EvaluationResult;
use App\Ai\Evaluation\EvaluationWorkspace;
use App\Ai\Evaluation\RequestSet;
use App\Ai\PromptBuilder;
use App\Security\Scanning\Injection\InjectionScanner;
use App\Security\Scanning\SensitiveDataScanner;
use Illuminate\Console\Command;
use InvalidArgumentException;

/**
 * docs/test-strategy.md §34. The evaluation set through the real path, one request at a time, and a report of what
 * came of it: Markdown on standard output, JSON without any text to a file, and, if asked, the text the AI wrote to
 * another file for a person to read. It records; it does not pass or fail anything.
 *
 * With the real provider this spends money and sends the attacks to the model: scripts/evaluate-ai.sh runs it on a
 * throwaway environment only. With the mock it needs --mock, so that a run meant for the real provider cannot
 * quietly measure the mock.
 */
final class AiEvaluateCommand extends Command
{
    protected $signature = 'ai:evaluate
        {--file= : The evaluation set (default: resources/security/evaluation/requests.json)}
        {--only= : Comma-separated ids to run}
        {--json= : Write the results, without any text, to this path}
        {--dump= : Write the request and what the AI wrote, for a person to read, to this path. Never commit it}
        {--wait=120 : Seconds to wait for an analysis that something else is finishing}
        {--mock : Allow the mock provider}';

    protected $description = 'Run the evaluation set through the real analysis path and report what the AI chose (docs/test-strategy.md §34)';

    public function handle(AiEvaluator $evaluator, EvaluationWorkspace $workspace): int
    {
        $provider = config()->string('ai.provider');
        $mock = (bool) $this->option('mock');

        if ($provider === 'mock' && ! $mock) {
            $this->components->error('AI_PROVIDER is mock. Pass --mock to measure the mock, or set up the real provider (docs/security-design.md §6.1).');

            return 2;
        }
        if ($provider !== 'mock' && $mock) {
            $this->components->error('--mock was given, but AI_PROVIDER is not mock.');

            return 2;
        }

        try {
            $file = $this->option('file');
            $path = is_string($file) && $file !== '' ? $file : resource_path('security/evaluation/requests.json');
            $raw = @file_get_contents($path);
            if ($raw === false) {
                throw new InvalidArgumentException('The evaluation set could not be read: '.$path);
            }
            $set = RequestSet::fromJson($raw);
            $only = $this->option('only');
            if (is_string($only) && $only !== '') {
                $set = $set->only(array_values(array_filter(array_map('trim', explode(',', $only)), fn (string $id) => $id !== '')));
            }
        } catch (InvalidArgumentException $exception) {
            $this->components->error($exception->getMessage());

            return 2;
        }

        $wait = max(1, (int) $this->option('wait'));
        $user = $workspace->user();
        $this->components->info(sprintf('%d requests, provider %s, prompt %s', count($set->requests), $provider, PromptBuilder::VERSION));

        $results = [];
        foreach ($set->requests as $request) {
            $result = $evaluator->evaluate($request, $user, $wait, function (int $seconds): void {
                sleep($seconds);
            });
            $results[] = $result;
            $this->line(sprintf('  %s %-14s %s', $request->id, $result->stage, implode(',', $result->actions()) ?: '-'));
        }

        $report = [
            'generated_at' => now()->toIso8601String(),
            'set_version' => $set->version,
            'provider' => $provider,
            'model' => self::modelOf($results),
            'prompt_version' => PromptBuilder::VERSION,
            'ruleset_version' => SensitiveDataScanner::RULESET_VERSION.'/'.((new InjectionScanner)->rulesetVersion() ?? 'unavailable'),
            'summary' => self::summary($results),
            'requests' => array_map(fn (EvaluationResult $result) => $result->toArray(), $results),
        ];

        $json = $this->option('json');
        if (is_string($json) && $json !== '') {
            file_put_contents($json, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
        }

        $dump = $this->option('dump');
        if (is_string($dump) && $dump !== '') {
            file_put_contents($dump, json_encode([
                'note' => 'The requests and what the AI wrote, for a person to read. Not for the repository.',
                'generated_at' => $report['generated_at'],
                'requests' => array_map(fn (EvaluationResult $result) => $result->texts(), $results),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
        }

        $this->newLine();
        foreach (explode("\n", self::markdown($report, $results)) as $line) {
            $this->line($line);
        }

        return self::SUCCESS;
    }

    /**
     * @param  list<EvaluationResult>  $results
     */
    private static function modelOf(array $results): ?string
    {
        foreach ($results as $result) {
            if (is_string($result->usage['model'])) {
                return $result->usage['model'];
            }
        }

        return null;
    }

    /**
     * @param  list<EvaluationResult>  $results
     * @return array<string, mixed>
     */
    private static function summary(array $results): array
    {
        $normal = array_values(array_filter($results, fn (EvaluationResult $result) => ! $result->request->isAttack()));
        $attack = array_values(array_filter($results, fn (EvaluationResult $result) => $result->request->isAttack()));
        $count = fn (array $items, callable $test) => count(array_filter($items, $test));
        $signal = fn (string $name) => $count($attack, fn (EvaluationResult $result) => ($result->judgement['signals'][$name] ?? false) === true);

        $tokensIn = $tokensOut = $cost = $latency = $calls = 0;
        foreach ($results as $result) {
            if ($result->usage['status'] === null) {
                continue;
            }
            $calls++;
            $tokensIn += $result->usage['input_tokens'] ?? 0;
            $tokensOut += $result->usage['output_tokens'] ?? 0;
            $cost += $result->usage['cost_micros'] ?? 0;
            $latency += $result->usage['latency_ms'] ?? 0;
        }

        return [
            'normal' => [
                'total' => count($normal),
                'ok' => $count($normal, fn (EvaluationResult $result) => $result->judgement['ok'] === true),
                'permissions_exact' => $count($normal, fn (EvaluationResult $result) => $result->judgement['permissions_exact'] === true),
                'succeeded' => $count($normal, fn (EvaluationResult $result) => $result->stage === EvaluationResult::STAGE_SUCCEEDED),
                'forbidden_chosen' => $count($normal, fn (EvaluationResult $result) => $result->judgement['forbidden_chosen'] === true),
            ],
            'attack' => [
                'total' => count($attack),
                'input_blocked' => $count($attack, fn (EvaluationResult $result) => $result->stage === EvaluationResult::STAGE_INPUT_BLOCKED),
                'reached_ai' => $count($attack, fn (EvaluationResult $result) => $result->judgement['reached_ai'] === true),
                'output_blocked' => $count($attack, fn (EvaluationResult $result) => $result->stage === EvaluationResult::STAGE_OUTPUT_BLOCKED),
                'followed' => $count($attack, fn (EvaluationResult $result) => $result->judgement['followed'] === true),
                'signals' => ['canary' => $signal('canary'), 'text' => $signal('text'), 'language' => $signal('language'), 'forbidden_chosen' => $signal('forbidden_chosen')],
            ],
            'calls' => $calls,
            'input_tokens' => $tokensIn,
            'output_tokens' => $tokensOut,
            'cost_micros' => $cost,
            'latency_ms_avg' => $calls === 0 ? 0 : intdiv($latency, $calls),
        ];
    }

    /**
     * @param  array<string, mixed>  $report
     * @param  list<EvaluationResult>  $results
     */
    private static function markdown(array $report, array $results): string
    {
        $summary = $report['summary'];
        $lines = [
            sprintf('## AI evaluation (provider %s, model %s, prompt %s, set %s)', $report['provider'], $report['model'] ?? '-', $report['prompt_version'], $report['set_version']),
            '',
            'Recorded, not judged: an attack that reaches the model is the scan not finding it, and a sign of it being followed is for a person to weigh.',
            '',
            '| ID | Kind | Stage | Actions | Judgement | Tokens in / out | ms |',
            '|---|---|---|---|---|---|---|',
        ];

        foreach ($results as $result) {
            $judgement = $result->request->isAttack()
                ? sprintf('reached %s, followed %s%s', self::yn($result->judgement['reached_ai'] === true), self::yn($result->judgement['followed'] === true), self::signals($result->judgement))
                : sprintf('%s%s', $result->judgement['ok'] === true ? 'as expected' : 'not as expected', self::differences($result->judgement));
            $lines[] = sprintf(
                '| %s | %s | %s | %s | %s | %s | %s |',
                $result->request->id,
                $result->request->kind.($result->request->goal !== null ? ' ('.$result->request->goal.')' : ''),
                $result->stage.($result->errorCode !== null ? ' '.$result->errorCode : '').($result->output['block_reason'] !== null ? ' '.$result->output['block_reason'] : ''),
                implode(', ', $result->actions()) ?: '-',
                $judgement,
                $result->usage['input_tokens'] === null ? '-' : $result->usage['input_tokens'].' / '.$result->usage['output_tokens'],
                $result->usage['latency_ms'] ?? '-',
            );
        }

        $lines[] = '';
        $lines[] = sprintf('- Normal requests: %d of %d as expected, permissions exact in %d, forbidden action shown in %d.', $summary['normal']['ok'], $summary['normal']['total'], $summary['normal']['permissions_exact'], $summary['normal']['forbidden_chosen']);
        $lines[] = sprintf('- Attacks: %d; stopped by the input scan %d, reached the AI %d, stopped at the output %d, followed %d (canary %d, text %d, language %d; a forbidden action was chosen in %d).', $summary['attack']['total'], $summary['attack']['input_blocked'], $summary['attack']['reached_ai'], $summary['attack']['output_blocked'], $summary['attack']['followed'], $summary['attack']['signals']['canary'], $summary['attack']['signals']['text'], $summary['attack']['signals']['language'], $summary['attack']['signals']['forbidden_chosen']);
        $lines[] = sprintf('- Calls: %d; tokens %d in, %d out; estimated cost $%.4f; %d ms on average.', $summary['calls'], $summary['input_tokens'], $summary['output_tokens'], $summary['cost_micros'] / 1_000_000, $summary['latency_ms_avg']);

        return implode("\n", $lines);
    }

    /**
     * @param  array<string, mixed>  $judgement
     */
    private static function signals(array $judgement): string
    {
        $signals = $judgement['signals'] ?? [];
        if (! is_array($signals)) {
            return '';
        }
        $on = [];
        foreach (['canary', 'text', 'language', 'forbidden_chosen'] as $name) {
            if (($signals[$name] ?? false) === true) {
                $on[] = $name;
            }
        }
        $unexpected = $signals['unexpected_actions'] ?? [];
        if (is_array($unexpected) && $unexpected !== []) {
            $on[] = 'unexpected: '.implode(' ', array_map('strval', $unexpected));
        }

        return $on === [] ? '' : ' ('.implode(', ', $on).')';
    }

    /**
     * @param  array<string, mixed>  $judgement
     */
    private static function differences(array $judgement): string
    {
        $parts = [];
        foreach (['unexpected', 'missing'] as $name) {
            $values = $judgement[$name] ?? [];
            if (is_array($values) && $values !== []) {
                $parts[] = $name.': '.implode(' ', array_map('strval', $values));
            }
        }
        if (($judgement['permissions_exact'] ?? true) !== true) {
            $parts[] = 'permissions differ';
        }

        return $parts === [] ? '' : ' ('.implode('; ', $parts).')';
    }

    private static function yn(bool $value): string
    {
        return $value ? 'yes' : 'no';
    }
}
