import { ApiError } from '../../api/client'
import type { Scan } from './workflowApi'

export const STATUS_LABELS: Record<string, string> = {
  draft: '下書き',
  pending: '承認待ち',
  approved: '承認済み',
  running: '実行中',
  completed: '完了',
  rejected: '却下',
  failed: '失敗',
}

export const PRIORITY_LABELS: Record<string, string> = { low: '低', medium: '中', high: '高' }

export const SEVERITY_LABELS: Record<string, string> = { low: '低', medium: '中', high: '高', critical: '重大' }

export const ACTION_LABELS: Record<string, string> = { record: '記録のみ', mask_continue: 'マスキングして続行', warn: '警告して続行', block: '停止' }

/** "Nothing found" is not "safe": this is always shown with the notice of what a scan cannot find. */
export function scanLabel(scan: Scan): string {
  switch (scan.decision) {
    case null:
      return '未検査'
    case 'block':
      return '停止'
    case 'warn':
      return '警告あり'
    default:
      if (scan.masking_status === 'masked') {
        return 'マスキング済み'
      }
      return scan.findings_count > 0 ? '記録あり' : '検出なし'
  }
}

const FIELD_LABELS: Record<string, string> = { title: 'タイトル', description: '説明', target_data: '対象データ', impact_summary: '影響', steps: '手順', requested_permissions: 'AI が申告した権限', action_type: '操作' }

/** "tasks.2.steps.1" as the screen calls it. A name it does not know is shown as it is, as text. */
export function fieldLabel(field: string): string {
  const [root, task, name, step] = field.split('.')

  if (root === 'title' && task === undefined) {
    return 'ワークフロー名'
  }
  if (root !== 'tasks' || task === undefined || name === undefined) {
    return field
  }

  return `タスク ${task} の${FIELD_LABELS[name] ?? name}${step === undefined ? '' : ` ${step}`}`
}

/** For choosing only. The server decides what each one is allowed to do. */
export const ACTION_TYPES = ['text.analyze', 'text.summarize', 'report.draft', 'task.create', 'email.send', 'file.delete', 'shell.exec', 'db.query', 'http.request']

const ANALYSIS_ERRORS: Record<string, string> = {
  AI_UNAVAILABLE: 'AI を利用できませんでした。しばらく待ってから再度お試しください。',
  AI_INVALID_OUTPUT: 'AI の応答が正しい形式ではなかったため、ワークフローを作成しませんでした。',
  AI_OUTPUT_BLOCKED: 'AI の応答に秘密情報や攻撃と思われる内容、またはシステムプロンプトの一部が含まれていたため、ワークフローを作成しませんでした。',
  USER_INACTIVE: 'このアカウントは無効です。',
  ANALYSIS_STALE: '処理が時間内に完了しませんでした。再度お試しください。',
  ANALYSIS_FAILED: '分析に失敗しました。再度お試しください。',
}

export function analysisErrorMessage(code: string | null): string {
  return (code !== null ? ANALYSIS_ERRORS[code] : undefined) ?? '分析に失敗しました。再度お試しください。'
}

const MASKED_TOO_LONG = 'マスキング後の文字数が上限を超えます。短くしてください。'

/** A fixed sentence for each case. What the server sent is only shown when it is a known field error. */
export function apiErrorMessage(error: unknown): string {
  if (!(error instanceof ApiError)) {
    return 'サーバーに接続できませんでした。'
  }

  switch (error.code) {
    case 'REVISION_CONFLICT':
      return '他の変更が先に保存されました。最新の内容を読み込みました。確認してからもう一度保存してください。'
    case 'WORKFLOW_INVALID_STATE':
      return '現在の状態ではこの操作を行えません。'
    case 'INPUT_BLOCKED':
      return '検査により処理を停止しました。何も保存していません。検出された箇所を確認してください。'
    case 'VALIDATION_FAILED':
      return Object.values(error.fieldErrors).flat().includes(MASKED_TOO_LONG) ? MASKED_TOO_LONG : '入力内容を確認してください。'
    case 'RATE_LIMITED':
      return '回数の上限に達しました。しばらく待ってから再度お試しください。'
    case 'FORBIDDEN':
      return 'この操作を行う権限がありません。'
    case 'NOT_FOUND':
      return '対象が見つかりません。'
    case 'SERVICE_UNAVAILABLE':
      return '現在サービスを利用できません。しばらく待ってから再度お試しください。'
    default:
      return '処理に失敗しました。'
  }
}
