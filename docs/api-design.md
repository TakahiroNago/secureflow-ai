# SecureFlow AI — API設計書

- 版：v1.3（2026-11-04）
- 状態：確定（v1.3：工程1-3 の監査記録の失敗時の応答、検証APIの応答を反映。v1.2：工程1-2 の認証設計を反映。v1.1：Q-D13・Q-PII・D11・Phase 0 追加条件を反映）

---

## 1. 共通仕様

| 項目 | 仕様 |
|---|---|
| ベースパス | `/api/v1` |
| 形式 | `application/json; charset=utf-8`。それ以外の Content-Type は 415 |
| 認証 | Laravel Sanctum SPA（同一オリジン Cookie セッション） |
| CSRF | 事前に `GET /sanctum/csrf-cookie`、状態変更リクエストは `X-XSRF-TOKEN` ヘッダ必須 |
| 成功レスポンス | `{ "data": ..., "meta": { ... } }` |
| エラーレスポンス | RFC 9457 Problem Details（下記） |
| ページング | カーソル方式 `?cursor=...&limit=20`（limit最大100） |
| 楽観ロック | 編集系は `If-Match: "<revision_no>"` 必須。不一致は 409 `REVISION_CONFLICT` |
| 冪等性 | 実行APIは `Idempotency-Key` ヘッダ必須（UUID推奨、最大100文字） |
| 時刻 | ISO 8601（UTC） |

### 1.1 エラー形式

```json
{
  "type": "https://secureflow.local/problems/plan-hash-mismatch",
  "title": "Plan hash mismatch",
  "status": 409,
  "code": "PLAN_HASH_MISMATCH",
  "detail": "承認対象の内容が変更されています。最新の内容を確認してください。",
  "trace_id": "0193...",
  "errors": { "field": ["..."] }
}
```

スタックトレース・SQL・ファイルパス・入力原文は**決して含めない**。

### 1.2 ステータスコード

| コード | 用途 |
|---|---|
| 200 / 201 / 202 | 成功 / 作成 / 非同期受付 |
| 401 | 未認証・セッション期限切れ・無効化されたユーザー、ログイン失敗（`AUTH_FAILED`。§3.1.1） |
| 403 | 認証済みだがロール不足（例：member が監査ログ参照）、自己承認 |
| 404 | 存在しない、または**別組織・別ユーザーのリソース**（存在の秘匿） |
| 409 | 状態不整合、リビジョン競合、ハッシュ不一致、二重実行 |
| 415 | Content-Type 不正 |
| 419 | CSRF トークンの不一致・期限切れ（`CSRF_TOKEN_MISMATCH`） |
| 422 | バリデーションエラー、入力検査による停止（`INPUT_BLOCKED`） |
| 429 | レート制限、AI利用上限超過 |
| 500 / 503 | 内部エラー（`INTERNAL_ERROR`） / AIプロバイダ利用不可、DB・監査・Redis を利用できない、認証情報を検証できない障害（`SERVICE_UNAVAILABLE`。[security-design.md §16.5.1](security-design.md)。詳細は返さない。**障害を `AUTH_FAILED` として返し続けない**） |

### 1.3 認可の処理順（全APIで必須）

1. `auth:sanctum` — 未認証は 401
2. `EnsureUserIsActive` — `is_active=false` のユーザーは、既存セッションも即時に破棄して 401。**アカウントロック中でも既存セッションは維持する**（ロックは新規ログインのみを止める。[security-design.md §12](security-design.md)）
3. 組織スコープ — すべてのクエリに `organization_id = 認証ユーザーの組織` を強制（グローバルスコープ）。範囲外は 404
4. Policy — コントローラの全アクションで `authorize()` を必須化。ユーザー所有・ロールを判定
5. FormRequest — 入力検証（未知フィールドは無視せず拒否）

**UUIDを知っていることはアクセス権の根拠にならない。** ルートの認可漏れは「全ルートに認証ミドルウェアとPolicyが設定されていること」を検査する自動テストで防ぐ（[test-strategy.md](test-strategy.md)）。

### 1.4 レート制限

| 対象 | 制限 | キー |
|---|---|---|
| `POST /auth/login` | 5回/分 | email + IP |
| `POST /auth/login` | 30回/分（工程1-3で追加。**実測に基づかない暫定値。** `AUDIT_LOGIN_IP_LIMIT_PER_MINUTE` で変更でき、負荷試験で見直す）。**現構成では利用者単位でなく全利用者の合計の上限である** | IP（IPv6 は `/64`） |
| `PATCH /account/password` | 5回/分 | ユーザー |
| `POST /analyses`、`POST /security/scan-preview` | 10回/分 | ユーザー |
| `POST /security/test-runs` | 3回/時 | 組織 |
| その他API | 60回/分 | ユーザー（未認証はIP） |

超過時は 429 と `Retry-After` を返し、監査ログ `rate_limit.exceeded` を記録する（工程2-7。未認証の超過は大量発生しうるため、キーごとに集約して記録する）。

IP 単位の制限は、NAT 配下など同じ送信元 IP を共有する利用者全員に合算される。**信頼できるリバースプロキシと接続元 IP の取得方法を確定するまで、公開環境へ移行しない。**影響と送信元 IP の前提は [security-design.md §16.5.4](security-design.md) を参照する。

## 2. ロール別アクセス

| リソース | admin | member | auditor |
|---|---|---|---|
| 自分のワークフロー作成・編集・提出・実行 | ○ | ○ | × |
| 組織内の他人のワークフロー参照 | ○（承認のため） | × | ○（参照のみ） |
| 承認・却下 | ○（**他ユーザーが作成したもののみ**。自分が作成したものは不可） | × | ×（承認権限なし） |
| セキュリティ検出結果 参照 | ○ | 自分のもののみ | ○ |
| 検出結果の対策状況更新 | ○ | × | × |
| セキュリティ自己診断 実行 | ○ | × | × |
| 自己診断結果 参照 | ○ | ○ | ○ |
| 監査ログ参照・検証 | ○ | × | ○ |
| AI利用状況 | 組織全体 | 自分のみ | 組織全体 |
| 設定変更 | ○ | × | × |
| 自分のパスワード変更 | ○ | ○ | ○ |

申請者と承認者は必ず別ユーザーである。組織内に作成者以外の有効な admin がいない場合、そのワークフローは承認できず、実行もできない。本書の「有効」は `is_active = true` を指し、`locked_until` によるロック中のユーザーを含む（ロックは新規ログインのみを止める）。

## 3. エンドポイント一覧

### 3.1 認証

| メソッド | パス | 権限 | 説明 |
|---|---|---|---|
| GET | `/sanctum/csrf-cookie` | 不要 | CSRF Cookie発行 |
| POST | `/api/v1/auth/login` | 不要 | `{email, password}`。成功時セッションID再生成。失敗は常に 401 `AUTH_FAILED`（§3.1.1） |
| POST | `/api/v1/auth/logout` | 認証 | セッションを破棄し、CSRF トークンを再生成。204 |
| GET | `/api/v1/auth/me` | 認証 | `{id, name, email, role, organization}` |
| PATCH | `/api/v1/account/password` | 認証 | `{current_password, new_password}`。他のセッションを無効化し、現在のセッションは維持（§3.1.2） |

#### 3.1.1 ログインの応答

| 状況 | 応答 |
|---|---|
| 成功 | 200 `{ "data": { id, name, email, role, organization } }`。セッションIDを再生成 |
| 存在しないメールアドレス、パスワード不一致、`is_active=false`、アカウントロック中（**必要な監査ログを記録できた場合**） | **すべて同じ** 401 `AUTH_FAILED`。どの理由かを応答から区別できないようにする |
| 形式の不正（必須項目なし、メール形式でない、長さの上限超過、未知のフィールド） | 422（アカウントの状態に関わらず同じ） |
| CSRF トークンなし・不一致、許可されていないオリジン（`SANCTUM_STATEFUL_DOMAINS` にない、オリジンなし） | 419 `CSRF_TOKEN_MISMATCH` |
| レート制限超過 | 429 と `Retry-After` |
| 監査の事前確認に失敗 | **認証情報の正否に関わらず** 503 `SERVICE_UNAVAILABLE` と `Retry-After`。ユーザーの検索とパスワードの検証を行わない |
| DB のエラーで認証情報を検証できない | 503 `SERVICE_UNAVAILABLE` と `Retry-After` |
| その他の内部障害 | 500 `INTERNAL_ERROR` |
| 認証の判定の後に必要な監査ログを追記できない（**認証の成否を問わない**） | 503 `SERVICE_UNAVAILABLE` と `Retry-After`。**成功と失敗で `trace_id` 以外の差を設けない。** 認証が成功していてもセッションを開始しない。失敗回数とロックは維持する（[security-design.md §16.5.1](security-design.md)） |
| Redis の停止・接続失敗・タイムアウト（**Origin なしの要求を含む**） | RFC 9457 形式の 503 `SERVICE_UNAVAILABLE` と `Retry-After`。**認証処理を継続しない**（fail closed）。レート制限を無効化して認証を続けることはない。**正常時の Origin と CSRF の検証の扱いは変更しない**（[security-design.md §16.5.1](security-design.md)） |

ログアウトは、監査記録に失敗してもセッションを破棄して 204 を返す。Redis が利用できない場合はセッションを破棄できないため 503 を返す（ログアウトは完了していない）。

```json
{
  "type": "https://secureflow.local/problems/service-unavailable",
  "title": "Service unavailable",
  "status": 503,
  "code": "SERVICE_UNAVAILABLE",
  "detail": "現在サービスを利用できません。しばらく待ってから再度お試しください。",
  "trace_id": "0193..."
}
```

**`PATCH /account/password` の 503 の案内：** この API の 503 は、原因とコミットの前後に関わらず、すべて同じ `detail` とする：「パスワード変更の結果を確認できませんでした。変更が確定している可能性があります。できるだけ早く、同じ内容・同じ冪等性キーで再試行してください。」（コミット後の失敗にだけ案内を出すと、現在のパスワードの正否を判別できるため）。クライアントは新しい `Idempotency-Key` を発行せず、同じキーで再試行する。

それ以外の API では、監査の利用不可と Redis の障害で、同じ形式と文言を使い、`Retry-After` を設定する。原因はサーバー側のログでのみ区別する。セッションを確認できない認証済み API も同じ 503 とする（fail closed）。Redis に依存しない `GET /api/health/live` は止めない。`GET /api/health/ready` は Redis の状態を反映して 503 `{"status":"unavailable"}` を返す（§3.10）。経路ごとの動作は [security-design.md §16.5.1](security-design.md) に定める。

```json
{
  "type": "https://secureflow.local/problems/auth-failed",
  "title": "Authentication failed",
  "status": 401,
  "code": "AUTH_FAILED",
  "detail": "メールアドレスまたはパスワードが正しくありません。",
  "trace_id": "0193..."
}
```

処理時間も区別できないよう、存在しないメールアドレス、無効、ロック中の場合もパスワードハッシュの検証を実行する。エラー形式は RFC 9457（§1.1）に従い、`Content-Type` は `application/problem+json` とする。認証エラー（401、419、422、429、415）の形式は工程1-2で実装し、全エラーの統一は工程2-9で行う。Cookie セッション専用のため Bearer トークンは受け付けない（未認証の 401）。

#### 3.1.2 パスワード変更

`Idempotency-Key`（UUID）ヘッダを必須とする（工程1-3で追加）。ない場合は 422。サーバーは平文で保存しない。有効期限は確定から15分（暫定値。[security-design.md §16.5.5](security-design.md)）。

| 状況 | 応答 |
|---|---|
| 成功 | 200 `{ "data": { "password_changed_at": "..." } }`。他のセッションを無効化し、**現在のセッションは維持**する（セッションIDは再生成）。コミット後に必須のセッションの保存に失敗した場合は下記の 503（[security-design.md §16.5.5](security-design.md)） |
| **DB のコミット後に必須のセッションの保存に失敗** | 503 `SERVICE_UNAVAILABLE` と `Retry-After`。**変更は取り消さない。** 保存されていないセッションIDの Cookie を返さない。同じキー・同じ内容で再試行する |
| 同じ `Idempotency-Key`・同じ内容の再試行（確定済み、期限内、`current_password` と `new_password` の両方が一致） | 再実行せず、同じ `password_changed_at` で 200。監査ログを追加しない。**セッションが利用できなければ 401 で、再ログインの後に再試行する** |
| 同じ `Idempotency-Key` で内容が異なる（`current_password` のみの違いを含む） | 409 `IDEMPOTENCY_KEY_CONFLICT`。変更しない |
| Redis の停止などで、コミットの前に処理できない | 503 `SERVICE_UNAVAILABLE` と `Retry-After`。パスワードは変更されない。同じキーで再試行できる |
| 監査の事前確認に失敗 | **現在のパスワードの正否に関わらず** 503 `SERVICE_UNAVAILABLE` と `Retry-After`。パスワードの検証と変更を行わない |
| 判定の後に必要な監査ログを追記できない（**現在のパスワードの正否を問わない**） | 503 `SERVICE_UNAVAILABLE` と `Retry-After`。変更をロールバックし、他のセッションも有効なまま。原因はサーバー側の重大ログで区別する（[security-design.md §16.5.1](security-design.md)） |
| DB のエラー、行ロック待ちの超過 | 503 `SERVICE_UNAVAILABLE` と `Retry-After`。同じキーで再試行できる |
| 現在のパスワードが不一致（`auth.password_change_failed` を記録できた場合） | 422 `CURRENT_PASSWORD_INVALID`。アカウントロックの失敗回数には数えない（レート制限で抑止） |
| 新しいパスワードがポリシー違反（12文字未満、長さの上限超過、漏洩パスワード辞書に一致、現在のパスワードと同じ） | 422 `errors.new_password` |
| 未認証 / CSRF トークンなし / レート制限超過 | 401 / 419 / 429 |

### 3.2 ダッシュボード・利用状況

| メソッド | パス | 権限 | 説明 |
|---|---|---|---|
| GET | `/api/v1/dashboard/summary` | 認証 | KPI（ワークフロー数、実行済み数、承認待ち数、未対応警告数、期間内検出数）、最近の操作、AI利用、最新自己診断結果。ロールに応じた範囲で集計 |
| GET | `/api/v1/ai-usage/summary?period=day\|month` | 認証 | 回数・トークン・推定費用・上限に対する割合 |

### 3.3 入力検査・AI分析

| メソッド | パス | 権限 | 説明 |
|---|---|---|---|
| POST | `/api/v1/security/scan-preview` | admin, member | AIを呼ばずに検査のみ。マスク済みテキストと検出結果を返す（送信前確認用）。scanは記録、本文は保存しない |
| POST | `/api/v1/analyses` | admin, member | 分析要求。202 で `analysis_id` を返す。入力検査の全体判定が `block`（認証・秘密情報の検出、インジェクション High/Critical、マスキング失敗）の場合は 422 `INPUT_BLOCKED` |
| GET | `/api/v1/analyses/{id}` | 本人 | `status`、`workflow_id`、`scan` 要約、`error_code` |

`POST /analyses` リクエスト：

```json
{ "input": "毎週の売上報告を作成して、重要な変化をまとめてください。" }
```

レスポンス（202）：

```json
{
  "data": {
    "id": "0193...",
    "status": "queued",
    "scan": {
      "decision": "allow",
      "max_severity": "medium",
      "masking_status": "masked",
      "masked_input": "担当 [EMAIL_REDACTED] 宛の...",
      "findings": [{ "category": "pii", "rule_id": "PII-EMAIL", "severity": "medium", "action": "mask_continue", "message": "メールアドレスを検出しマスキングしました" }],
      "limitations_notice": "検出は完全ではなく、氏名・住所など自動検出できない個人情報や秘密情報が含まれている可能性があります。検出されなかった情報が存在しないことは保証されません。"
    }
  }
}
```

認証・秘密情報を検出した場合のレスポンス（422）：

```json
{
  "type": "https://secureflow.local/problems/input-blocked",
  "title": "Input blocked",
  "status": 422,
  "code": "INPUT_BLOCKED",
  "detail": "認証情報・秘密情報と思われる文字列が含まれているため処理を停止しました。該当箇所を削除して再度入力してください。",
  "trace_id": "0193...",
  "scan": {
    "decision": "block",
    "block_reason": "SECRET_DETECTED",
    "max_severity": "critical",
    "findings": [{ "category": "secret", "rule_id": "SEC-APIKEY", "severity": "critical", "action": "block", "position_start": 12, "position_end": 31, "message": "APIキー形式の文字列を検出しました" }],
    "limitations_notice": "..."
  }
}
```

- 停止時は `masked_input` を返さない（秘密情報の周辺文脈も返さない）。位置情報のみを返し、画面側は利用者がまだ保持している入力欄の該当箇所を示す。
- `severity`（重大度）と `action`（処理動作）は常に別フィールドで返す。処理の流れを表すのは `decision` と各 finding の `action` であり、`severity` から判断しない。
- `limitations_notice` は入力検査・分析・ワークフロー詳細・承認コンテキストのレスポンスで、検出の有無にかかわらず**常に返す**（[security-design.md §4](security-design.md)）。

### 3.4 ワークフロー

| メソッド | パス | 権限 | 説明 |
|---|---|---|---|
| GET | `/api/v1/workflows?status=&cursor=` | 認証 | member は自分のもののみ。admin/auditor は組織内 |
| GET | `/api/v1/workflows/{id}` | 所有者 / admin / auditor | 現在のタスク、current_revision（no, plan_hash, scan）、状態 |
| PATCH | `/api/v1/workflows/{id}` | 所有者 | タイトル変更（実行計画外のためリビジョンを作らない）。`If-Match` 必須 |
| PUT | `/api/v1/workflows/{id}/tasks/{taskId}` | 所有者 | タスク編集。新リビジョン作成・再検査・状態を Draft に戻す。`If-Match` 必須 |
| POST | `/api/v1/workflows/{id}/tasks` | 所有者 | タスク追加（同上） |
| DELETE | `/api/v1/workflows/{id}/tasks/{taskId}` | 所有者 | タスク削除（同上） |
| POST | `/api/v1/workflows/{id}/submit` | 所有者 | Draft→Pending。forbidden 操作含む場合 409 `FORBIDDEN_ACTION_PRESENT`、検査 block の場合 409 `SCAN_BLOCKED` |
| POST | `/api/v1/workflows/{id}/reopen` | 所有者 | Rejected/Failed→Draft（新リビジョン） |
| GET | `/api/v1/workflows/{id}/history` | 所有者 / admin / auditor | リビジョン・承認・実行の時系列 |

編集可能な項目：`title`, `description`, `action_type`（ActionCatalogの値のみ）, `steps`, `priority`, `target_data`, `impact_summary`。`derived_permissions`・`policy_decision` はクライアントから受け付けない（サーバー導出）。ユーザー編集内容にも入力検査（マスキング・認証情報検出・インジェクション検出）を適用し、全体判定が `block` の場合は編集を保存せず 422 `INPUT_BLOCKED` を返す。

提出（submit）時、組織内に承認可能な admin（作成者以外の有効な admin）がいない場合も提出は受け付けるが、レスポンスに `"approver_available": false` を含め、画面に「承認可能な管理者がいないため、このワークフローは承認・実行できません」と表示する。

### 3.5 承認

| メソッド | パス | 権限 | 説明 |
|---|---|---|---|
| GET | `/api/v1/approvals?status=pending` | admin | 承認待ち一覧（自分が作成者のものは `can_approve=false`、理由 `SELF_CREATED` 付き） |
| GET | `/api/v1/workflows/{id}/approval-context` | admin / 所有者 | 承認画面表示内容（下記）。所有者には参照のみ（`can_approve=false`） |
| POST | `/api/v1/workflows/{id}/approve` | admin（他ユーザーが作成したもののみ） | 下記 |
| POST | `/api/v1/workflows/{id}/reject` | admin（他ユーザーが作成したもののみ） | `{revision_no, plan_hash, reason}` |

`cannot_approve_reason` の値：`SELF_CREATED`（自分が作成者）、`ROLE_NOT_ADMIN`（admin 以外）、`INVALID_STATE`（Pending でない）、`FORBIDDEN_ACTION_PRESENT`、`SCAN_BLOCKED`。

`approval-context` には `approver_available`（組織内に作成者以外の有効な admin が存在するか）を含める。

`approval-context` レスポンス（要件4.5の表示6項目）：

```json
{
  "data": {
    "workflow_id": "0193...",
    "revision_no": 3,
    "plan_hash": "9f2c...e1",
    "policy_version": "2026.11.1",
    "tasks": [{
      "position": 1,
      "title": "週次売上レポート下書き作成",
      "action_type": "report.draft",
      "ai_feature": "テキスト要約・レポート下書き生成（模擬実行）",
      "target_data": "週次売上データの説明文（マスク済み）",
      "derived_permissions": ["ai.text.read", "report.draft.write"],
      "impact_summary": "下書きを生成するのみ。外部送信なし",
      "policy_decision": "allowed"
    }],
    "security": { "max_severity": "medium", "decision": "warn", "findings": [ ... ], "limitations_notice": "..." },
    "requires_risk_acknowledgement": true,
    "created_by": { "id": "0193...", "name": "申請者" },
    "can_approve": true,
    "cannot_approve_reason": null,
    "approver_available": true
  }
}
```

`approve` リクエスト：

```json
{ "revision_no": 3, "plan_hash": "9f2c...e1", "acknowledged_risks": true, "comment": "確認済み" }
```

| 失敗条件 | 応答 |
|---|---|
| member / auditor による承認・却下 | 403 `APPROVER_ROLE_REQUIRED` |
| 作成者本人（admin であっても） | 403 `SELF_APPROVAL_FORBIDDEN` |
| 承認者が無効化（`is_active=false`） | 401（セッション破棄）。処理中に無効化された場合は 403 |
| 状態が Pending でない | 409 `WORKFLOW_INVALID_STATE` |
| revision_no / plan_hash 不一致 | 409 `PLAN_HASH_MISMATCH` |
| 同一リビジョンに決定済み（同時承認） | 409 `ALREADY_DECIDED` |
| Medium以上で `acknowledged_risks=false` | 422 `RISK_ACK_REQUIRED` |

### 3.6 実行

| メソッド | パス | 権限 | 説明 |
|---|---|---|---|
| POST | `/api/v1/workflows/{id}/execute` | 所有者 / admin | `Idempotency-Key` 必須。再検証後 202 `{execution_id}` |
| GET | `/api/v1/workflows/{id}/executions` | 所有者 / admin / auditor | 実行履歴と模擬実行結果 |

| 失敗条件 | 応答 |
|---|---|
| 実行者が無効化（`is_active=false`） | 401（セッション破棄）。処理中に無効化された場合は 403 |
| 有効な承認なし（未承認・承認無効化済み） | 409 `APPROVAL_NOT_VALID` |
| 再計算ハッシュ不一致 | 409 `PLAN_HASH_MISMATCH` |
| ポリシー再照合で forbidden | 409 `POLICY_VIOLATION` |
| 既に実行済み・実行中 | 409 `EXECUTION_ALREADY_EXISTS` |
| 同一 Idempotency-Key・同一内容の再送 | 202（既存 execution を返す） |
| 同一 Idempotency-Key・別ワークフロー | 422 `IDEMPOTENCY_KEY_REUSED` |

### 3.7 セキュリティ管理

| メソッド | パス | 権限 | 説明 |
|---|---|---|---|
| GET | `/api/v1/security/findings?severity=&status=&category=&cursor=` | admin / auditor / member（自分のみ） | 検出一覧 |
| PATCH | `/api/v1/security/findings/{id}` | admin | `{status, status_note}`。監査ログ記録 |
| GET | `/api/v1/security/scans/{id}` | 対象リソースの参照権限者 | |
| POST | `/api/v1/security/test-runs` | admin | 自己診断開始。202 |
| GET | `/api/v1/security/test-runs` / `/{id}` | 認証 | 結果一覧・詳細 |

### 3.8 監査ログ

| メソッド | パス | 権限 | 説明 |
|---|---|---|---|
| GET | `/api/v1/audit-logs?event_type=&actor_user_id=&result=&severity=&from=&to=&cursor=` | admin / auditor | 組織内のみ。更新・削除APIは**存在しない** |
| POST | `/api/v1/audit-logs/verify` | admin / auditor | 工程2-7で実装。**認証ユーザーの組織のチェーンのみ**検証する。`{valid, checked_count, first_broken_seq, reason_code}`（`id` はチェーン順序ではないため返さない）。`chain_id` を入力として受け取らず、システムチェーンは検証・参照できない |

### 3.9 設定

| メソッド | パス | 権限 | 説明 |
|---|---|---|---|
| GET | `/api/v1/settings/ai` | admin | `{provider, model, api_key_configured: true/false, timeout, max_output_tokens}`。**キー値・末尾桁も返さない** |
| GET / PATCH | `/api/v1/settings/limits` | admin | 月間トークン上限、ユーザー日次上限、最大入力長 |
| GET | `/api/v1/settings/security` | admin | リスク判定方針・ルールセット版・ポリシー版（参照のみ。D4により固定） |

プロバイダ・モデル・送信先URL・APIキーは環境変数で管理し、APIからは変更できない（D5・SSRF対策）。

### 3.10 ヘルスチェック

| メソッド | パス | 権限 | 説明 |
|---|---|---|---|
| GET | `/api/health/live` | 不要 | Liveness。プロセスが応答できれば 200 `{"status":"ok"}`。外部依存は確認しない |
| GET | `/api/health/ready` | 不要 | Readiness。DB（appロールで `SELECT 1`）と Redis（`PING`）に到達できれば 200 `{"status":"ok"}`、いずれか不可なら 503 `{"status":"unavailable"}` |

**応答形式：** 通常の API エラーは RFC 9457 形式（§1.1）とする。**ヘルスチェックは監視用のため、工程0で確定したこの形式を維持する。** readiness の 503 に内部情報、接続文字列、例外メッセージを含めない。監視側は HTTP ステータスコードと `status` で判定する。Audit unavailable の間、設定・権限の不備では readiness は 200 のままのため、監査の障害は別の信号で監視する。ストレージの障害の疑い（`storage_scope=db_suspected`）の間は readiness も 503 とする。**liveness は 200 を維持する。readiness の 503 を理由にコンテナを自動で再起動しない**（[security-design.md §16.5.1・§16.5.3](security-design.md)）。

どちらもバージョン・ホスト名・接続先・エラー詳細・どの依存が失敗したかを返さない。認証不要のためレート制限（IP単位 60回/分）を適用する。失敗の詳細はアプリケーションログにのみ記録する。
