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
  AI_LIMIT_EXCEEDED: 'AI の利用上限に達したため、分析しませんでした。',
  AI_OUTPUT_BLOCKED: 'AI の応答に秘密情報や攻撃と思われる内容、またはシステムプロンプトの一部が含まれていたため、ワークフローを作成しませんでした。',
  USER_INACTIVE: 'このアカウントは無効です。',
  ANALYSIS_STALE: '処理が時間内に完了しませんでした。再度お試しください。',
  ANALYSIS_FAILED: '分析に失敗しました。再度お試しください。',
}

export function analysisErrorMessage(code: string | null): string {
  return (code !== null ? ANALYSIS_ERRORS[code] : undefined) ?? '分析に失敗しました。再度お試しください。'
}

export const NO_APPROVER_MESSAGE = '承認可能な管理者がいないため、このワークフローは承認・実行できません。'

export const CANNOT_APPROVE_LABELS: Record<string, string> = {
  SELF_CREATED: '自分が作成したワークフローは承認できません。',
  ROLE_NOT_ADMIN: '承認できるのは管理者のみです。この画面は参照のみです。',
  INVALID_STATE: '現在の状態では承認できません。',
  FORBIDDEN_ACTION_PRESENT: '禁止された操作が含まれているため承認できません。',
  SCAN_BLOCKED: '検査で停止と判定されたため承認できません。',
  SCAN_REQUIRED: '未検査のリビジョンのため承認できません。',
  PLAN_HASH_MISMATCH: '保存された計画と内容が一致しないため承認できません。',
}

export const EXECUTION_STATUS_LABELS: Record<string, string> = { queued: '実行待ち', running: '実行中', completed: '完了', failed: '失敗' }

const EXECUTION_ERRORS: Record<string, string> = {
  EXECUTION_STALE: '処理が時間内に完了しなかったため、失敗として扱いました。',
  EXECUTION_PLAN_CHANGED: '承認された内容と一致しなかったため、実行しませんでした。',
  EXECUTION_NO_HANDLER: '実行できない操作が含まれていたため、実行を中止しました。',
  USER_INACTIVE: '実行を依頼した利用者が無効になったため、実行しませんでした。',
}

export function executionErrorMessage(code: string | null): string {
  return (code !== null ? EXECUTION_ERRORS[code] : undefined) ?? '実行に失敗しました。'
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
    case 'APPROVAL_NOT_VALID':
      return '有効な承認がないため実行できません。'
    case 'EXECUTION_ALREADY_EXISTS':
      return 'この承認はすでに実行に使われています。もう一度実行するには、下書きに戻して再度承認を受けてください。'
    case 'POLICY_VIOLATION':
      return 'ポリシーの確認で実行できませんでした。編集して保存し、再度承認を受けてください。'
    case 'IDEMPOTENCY_KEY_REUSED':
      return '実行の依頼を処理できませんでした。ページを再読み込みしてください。'
    case 'PLAN_HASH_MISMATCH':
      return '内容が変更されています。最新の内容を読み込みました。確認してからもう一度操作してください。'
    case 'ALREADY_DECIDED':
      return 'このリビジョンはすでに承認または却下されています。'
    case 'RISK_ACK_REQUIRED':
      return 'リスクを確認してから承認してください。'
    case 'SCAN_REQUIRED':
      return '未検査のリビジョンは提出、承認できません。編集して保存すると計画全体を検査します。'
    case 'SCAN_BLOCKED':
      return '検査で停止と判定されたリビジョンは提出、承認できません。'
    case 'FORBIDDEN_ACTION_PRESENT':
      return '禁止された操作を含むワークフローは提出、承認できません。該当するタスクを編集してください。'
    case 'APPROVER_ROLE_REQUIRED':
      return '承認または却下する権限がありません。'
    case 'SELF_APPROVAL_FORBIDDEN':
      return '自分が作成したワークフローは承認または却下できません。'
    case 'WORKFLOW_INVALID_STATE':
      return '現在の状態ではこの操作を行えません。'
    case 'SELF_TEST_RUNNING':
      return '自己診断を実行中です。完了してから再度実行してください。'
    case 'INVALID_STATUS_TRANSITION':
      return '現在の対策状況からその状態には変更できません。最新の状態を読み込んでください。'
    case 'INPUT_BLOCKED':
      return '検査により処理を停止しました。何も保存していません。検出された箇所を確認してください。'
    case 'VALIDATION_FAILED':
      return Object.values(error.fieldErrors).flat().includes(MASKED_TOO_LONG) ? MASKED_TOO_LONG : '入力内容を確認してください。'
    case 'AI_LIMIT_EXCEEDED':
      return 'AI の利用上限に達しました。上限が戻るまで分析できません。'
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
