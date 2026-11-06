/**
 * Until step 2-3 nothing is scanned or masked, and edited text is stored as typed (docs/development-roadmap.md §3).
 * This stays on screen for as long as that is true.
 */
export function UnscannedNotice() {
  return (
    <p role="alert" className="rounded-md bg-amber-50 p-3 text-sm text-amber-900 ring-1 ring-amber-200">
      入力検査は未実装です。機密情報や個人情報を入力しないでください。AI はモックであり、入力の内容は結果に反映されません。
    </p>
  )
}
