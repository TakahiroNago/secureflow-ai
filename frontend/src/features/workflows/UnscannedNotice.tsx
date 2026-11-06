/**
 * A revision from before step 2-3 was stored as typed, with no scan (docs/development-roadmap.md §3). This shows
 * only there: what is saved now is scanned and masked. Such a revision cannot be submitted, approved or run.
 */
export function UnscannedNotice() {
  return (
    <p role="alert" className="rounded-md bg-amber-50 p-3 text-sm text-amber-900 ring-1 ring-amber-200">
      このリビジョンは検査を導入する前に保存されたもので、未検査です。提出、承認、実行はできません。編集して保存すると、計画全体を検査します。
    </p>
  )
}
