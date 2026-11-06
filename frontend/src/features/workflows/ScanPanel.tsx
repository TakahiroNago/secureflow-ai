import type { Finding, Scan } from './workflowApi'
import { ACTION_LABELS, fieldLabel, scanLabel, SEVERITY_LABELS } from './labels'

type Props = {
  scan: Scan
  /** Points at a finding in the text the user still has. Only there is a text to point into. */
  onLocate?: (finding: Finding) => void
}

/**
 * What a scan found, and always what it cannot find (docs/security-design.md §4). "Nothing found" is never
 * shown without the notice: it does not mean the text is safe. Everything here is drawn as text.
 */
export function ScanPanel({ scan, onLocate }: Props) {
  const hidden = scan.findings_count - scan.findings.length

  return (
    <div className="space-y-2 rounded-md p-3 text-sm ring-1 ring-slate-200">
      <p>
        <span className="text-slate-500">検査の結果：</span>
        <span className="font-medium">{scanLabel(scan)}</span>
      </p>

      {scan.findings.length > 0 && (
        <ul className="space-y-1">
          {scan.findings.map((finding, index) => (
            <li key={index} className="flex flex-wrap items-center gap-2">
              <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs">重大度：{SEVERITY_LABELS[finding.severity]}</span>
              <span className="rounded bg-slate-100 px-1.5 py-0.5 text-xs">処理：{ACTION_LABELS[finding.action]}</span>
              {finding.field !== null && <span className="text-xs text-slate-500">{fieldLabel(finding.field)}</span>}
              <span>{finding.message}</span>
              {onLocate !== undefined && finding.position_start !== null && (
                <button
                  type="button"
                  className="text-xs underline"
                  onClick={() => {
                    onLocate(finding)
                  }}
                >
                  該当箇所を選択
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {hidden > 0 && <p className="text-xs text-slate-500">ほかに {hidden} 件の検出があります（表示は上限までです）。</p>}

      {scan.masked_input !== undefined && (
        <div>
          <p className="text-xs text-slate-500">保存・送信される内容（マスキング後）</p>
          <p className="mt-1 whitespace-pre-wrap rounded bg-slate-50 p-2">{scan.masked_input}</p>
        </div>
      )}

      <p className="text-xs text-slate-500">{scan.limitations_notice}</p>
    </div>
  )
}
