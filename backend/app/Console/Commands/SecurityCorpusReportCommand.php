<?php

namespace App\Console\Commands;

use App\Security\Scanning\Corpus\CorpusEvaluation;
use Illuminate\Console\Command;

/**
 * docs/test-strategy.md §7, §31. The corpus evaluation as a report: Markdown on standard output (the CI job puts it
 * in its summary) and, if asked, JSON to a file (the CI artifact). It exits 0 whatever the figures: the gates are
 * the tests. The hold-out rate is printed beside the tuning rate every time, and never counts as achieved.
 */
final class SecurityCorpusReportCommand extends Command
{
    protected $signature = 'security:corpus-report {--json= : Also write the report as JSON to this path}';

    protected $description = 'Measure the detectors against the corpus and print the report (docs/test-strategy.md §7)';

    public function handle(CorpusEvaluation $evaluation): int
    {
        $report = $evaluation->report();

        $json = $this->option('json');
        if (is_string($json) && $json !== '') {
            file_put_contents($json, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n");
        }

        foreach (explode("\n", $this->markdown($report)) as $line) {
            $this->line($line);
        }

        return self::SUCCESS;
    }

    /**
     * @param  array<string, mixed>  $report
     */
    private function markdown(array $report): string
    {
        $pct = fn (float $rate) => sprintf('%.1f%%', 100 * $rate);
        $mark = fn (bool $passed, bool $gate) => $gate ? ($passed ? 'pass' : '**FAIL**') : ($passed ? 'report only (met)' : 'report only (not met)');

        $tuning = $report['injection']['tuning'];
        $holdout = $report['injection']['holdout'];
        $injectionBusiness = $report['injection']['business'];
        $injectionBusinessEn = $report['injection']['business_en'];
        $sensitive = $report['sensitive']['samples'];
        $sensitiveBusiness = $report['sensitive']['business'];
        $sensitiveBusinessEn = $report['sensitive']['business_en'];

        $lines = [
            '## Corpus evaluation ('.$report['ruleset_version'].')',
            '',
            'The targets are on this corpus and say nothing about text that is not in it. The hold-out set was not used to tune the rules; its rate is what the rules do to new wording, and it is never counted as achieved by the tuning rate. The English business set (step 3-2) is reported only: the rules were tuned on Japanese text.',
            '',
            '| Metric | Value | Target | Status |',
            '|---|---|---|---|',
            sprintf('| Injection found at Medium or more, tuning | %d / %d (%s) | >= %s | %s |', $tuning['found'], $tuning['total'], $pct($tuning['rate']), $pct($tuning['target']), $mark($tuning['passed'], true)),
            sprintf('| Injection found at Medium or more, **hold-out** | %d / %d (%s) | >= %s | %s |', $holdout['found'], $holdout['total'], $pct($holdout['rate']), $pct($holdout['target']), $mark($holdout['passed'], false)),
            sprintf('| Business text stopped by injection rules | %d / %d (%s) | <= %s | %s |', count($injectionBusiness['stopped']), $injectionBusiness['total'], $pct($injectionBusiness['stopped_rate']), $pct($injectionBusiness['stopped_max']), $mark($injectionBusiness['passed'], true)),
            sprintf('| Business text flagged Medium or more by injection rules | %d / %d (%s) | <= %s | %s |', count($injectionBusiness['flagged']), $injectionBusiness['total'], $pct($injectionBusiness['flagged_rate']), $pct($injectionBusiness['flagged_max']), $mark($injectionBusiness['passed'], true)),
            sprintf('| **English** business text stopped by injection rules | %d / %d (%s) | <= %s | %s |', count($injectionBusinessEn['stopped']), $injectionBusinessEn['total'], $pct($injectionBusinessEn['stopped_rate']), $pct($injectionBusinessEn['stopped_max']), $mark($injectionBusinessEn['passed'], false)),
            sprintf('| **English** business text flagged Medium or more by injection rules | %d / %d (%s) | <= %s | %s |', count($injectionBusinessEn['flagged']), $injectionBusinessEn['total'], $pct($injectionBusinessEn['flagged_rate']), $pct($injectionBusinessEn['flagged_max']), $mark($injectionBusinessEn['passed'], false)),
            sprintf('| Sensitive samples found by every rule named | %d missed of %d | 0 missed | %s |', count($sensitive['missed']), $sensitive['samples'], $mark($sensitive['passed'], true)),
            sprintf('| Secrets stopped | %d / %d | all | %s |', $sensitive['blocked'], $sensitive['blockable'], $mark($sensitive['passed'], true)),
            sprintf('| Business text stopped by sensitive-data rules | %d / %d (%s) | <= %s | %s |', count($sensitiveBusiness['stopped']), $sensitiveBusiness['total'], $pct($sensitiveBusiness['stopped_rate']), $pct($sensitiveBusiness['stopped_max']), $mark($sensitiveBusiness['passed'], true)),
            sprintf('| Business text with any sensitive-data detection | %d / %d (%s) | <= %s | %s |', count($sensitiveBusiness['flagged']), $sensitiveBusiness['total'], $pct($sensitiveBusiness['flagged_rate']), $pct($sensitiveBusiness['flagged_max']), $mark($sensitiveBusiness['passed'], true)),
            sprintf('| **English** business text stopped by sensitive-data rules | %d / %d (%s) | <= %s | %s |', count($sensitiveBusinessEn['stopped']), $sensitiveBusinessEn['total'], $pct($sensitiveBusinessEn['stopped_rate']), $pct($sensitiveBusinessEn['stopped_max']), $mark($sensitiveBusinessEn['passed'], false)),
            sprintf('| **English** business text with any sensitive-data detection | %d / %d (%s) | <= %s | %s |', count($sensitiveBusinessEn['flagged']), $sensitiveBusinessEn['total'], $pct($sensitiveBusinessEn['flagged_rate']), $pct($sensitiveBusinessEn['flagged_max']), $mark($sensitiveBusinessEn['passed'], false)),
            '',
        ];

        foreach (['tuning' => $tuning['missed'], 'hold-out' => $holdout['missed']] as $set => $missed) {
            if ($missed !== []) {
                $lines[] = sprintf('<details><summary>Missed %s attacks (%d)</summary>', $set, count($missed));
                $lines[] = '';
                foreach ($missed as $attack) {
                    $lines[] = '- `'.str_replace('`', '\\`', $attack).'`';
                }
                $lines[] = '';
                $lines[] = '</details>';
                $lines[] = '';
            }
        }

        foreach (['injection rules' => $injectionBusiness['flagged'], 'sensitive-data rules' => $sensitiveBusiness['flagged'], 'injection rules (English)' => $injectionBusinessEn['flagged'], 'sensitive-data rules (English)' => $sensitiveBusinessEn['flagged']] as $rules => $flagged) {
            if ($flagged !== []) {
                $lines[] = sprintf('<details><summary>Business text flagged by %s (%d)</summary>', $rules, count($flagged));
                $lines[] = '';
                foreach ($flagged as $sentence) {
                    $lines[] = '- `'.str_replace('`', '\\`', $sentence).'`';
                }
                $lines[] = '';
                $lines[] = '</details>';
                $lines[] = '';
            }
        }

        return implode("\n", $lines);
    }
}
