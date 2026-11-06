import { ApiError } from '../../api/client'

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

/** For choosing only. The server decides what each one is allowed to do. */
export const ACTION_TYPES = ['text.analyze', 'text.summarize', 'report.draft', 'task.create', 'email.send', 'file.delete', 'shell.exec', 'db.query', 'http.request']

const ANALYSIS_ERRORS: Record<string, string> = {
  AI_UNAVAILABLE: 'AI を利用できませんでした。しばらく待ってから再度お試しください。',
  AI_INVALID_OUTPUT: 'AI の応答が正しい形式ではなかったため、ワークフローを作成しませんでした。',
  USER_INACTIVE: 'このアカウントは無効です。',
  ANALYSIS_STALE: '処理が時間内に完了しませんでした。再度お試しください。',
  ANALYSIS_FAILED: '分析に失敗しました。再度お試しください。',
}

export function analysisErrorMessage(code: string | null): string {
  return (code !== null ? ANALYSIS_ERRORS[code] : undefined) ?? '分析に失敗しました。再度お試しください。'
}

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
    case 'VALIDATION_FAILED':
      return '入力内容を確認してください。'
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
