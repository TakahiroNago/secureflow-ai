# SecureFlow AI — データベース設計書

- 版：v1.1（2026-11-03）
- 状態：確定（v1.1：Q-D13・Q-PII・D11・Phase 0 追加条件を反映）
- DBMS：PostgreSQL（実装時点の最新安定版）

---

## 1. 設計方針

1. **主キーは UUIDv7**（`audit_logs` のみ連番 + `event_id` UUID）。UUIDは列挙耐性のための補助であり、**認可の代わりにしない**（[security-design.md §13](security-design.md)）。
2. **全業務テーブルに `organization_id`** を持たせ、組織スコープでのデータ分離を徹底する。
3. **履歴系テーブルは追記専用**（UPDATE/DELETE をDB権限とトリガーの両方で拒否）。
4. **原文・秘密情報を保存しない。** ユーザー入力由来の本文はマスキング後のもののみ。
5. 時刻はすべて `timestamptz`（UTC保存、表示時にJST変換）。
6. 列挙値は `varchar` + `CHECK` 制約（PostgreSQLのENUM型は変更が重いため不採用）。
7. 楽観ロック用 `lock_version` と、行ロック（`SELECT ... FOR UPDATE`）を併用する。

## 2. ER概要

```
organizations 1─1 organization_settings
organizations 1─* users
organizations 1─* workflows ─1─* workflow_revisions ─1─0..1 approvals ─1─0..1 workflow_executions
                     │                 │
                     ├─1─* workflow_tasks（現在の編集用作業セット）
                     └─ current_revision_id ─▶ workflow_revisions
users 1─* ai_analysis_requests ─0..1─▶ workflows
security_scans 1─* security_findings     （対象：input / output / revision / self_test）
audit_logs（全イベント・追記専用・ハッシュチェーン）
ai_usage_logs（AI呼び出し記録・追記専用）
security_test_runs 1─* security_test_results
```

**タスクとリビジョンの関係：**
`workflow_tasks` は現在の編集用の作業セット（可変）。編集のたびに正規化スナップショットを `workflow_revisions.plan_snapshot` に**不変レコード**として保存し、そのハッシュを承認対象とする。**模擬実行は承認されたリビジョンのスナップショットのみを入力とする**（可変テーブルを実行に使わない）。実行直前には現在のタスクから再計算したハッシュと承認ハッシュを照合し、乖離を検出する。

## 3. テーブル定義

### 3.1 organizations

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK | |
| name | varchar(100) | NOT NULL | |
| created_at / updated_at | timestamptz | NOT NULL | |

### 3.2 organization_settings

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| organization_id | uuid | PK, FK | |
| monthly_token_limit | integer | NOT NULL, CHECK > 0 | 組織の月間トークン上限 |
| user_daily_request_limit | integer | NOT NULL, CHECK > 0 | ユーザーごとの1日のAI分析回数上限 |
| max_input_chars | integer | NOT NULL DEFAULT 4000, CHECK 1..20000 | 入力最大長 |
| updated_by | uuid | FK users NULL | |
| updated_at | timestamptz | NOT NULL | |

※ リスク判定閾値（D4）と自己承認禁止（D1）は**設定値にせずコードで固定**する。設定変更は監査ログに記録する。

### 3.3 users

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK | |
| organization_id | uuid | FK NOT NULL | |
| name | varchar(100) | NOT NULL | |
| email | citext | UNIQUE NOT NULL | ログインID |
| password | varchar(255) | NOT NULL | Argon2id ハッシュ |
| role | varchar(16) | CHECK IN ('admin','member','auditor') | |
| is_active | boolean | NOT NULL DEFAULT true | |
| failed_login_count | smallint | NOT NULL DEFAULT 0 | |
| locked_until | timestamptz | NULL | アカウントロック |
| last_login_at / password_changed_at | timestamptz | NULL | |
| created_at / updated_at | timestamptz | NOT NULL | |

セッションは Redis に保存する（`sessions` テーブルは使用しない）。

### 3.4 ai_analysis_requests

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK | |
| organization_id / user_id | uuid | FK NOT NULL | |
| status | varchar(16) | CHECK IN ('queued','processing','succeeded','blocked','failed') | |
| input_masked | text | NULL | マスク済み入力。**処理完了時に NULL 化**。入力検査で block となった場合はレコードを作成しない（スキャン結果のみ保存） |
| input_char_count | integer | NOT NULL | |
| input_scan_id | uuid | FK security_scans NULL | |
| output_scan_id | uuid | FK security_scans NULL | |
| workflow_id | uuid | FK NULL | 成功時に設定 |
| error_code | varchar(64) | NULL | 内部情報を含まないコード |
| started_at / heartbeat_at / finished_at | timestamptz | NULL | 停滞回収用 |
| created_at / updated_at | timestamptz | NOT NULL | |

### 3.5 workflows

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK | |
| organization_id | uuid | FK NOT NULL | |
| created_by | uuid | FK users NOT NULL | |
| title | varchar(200) | NOT NULL | |
| source_input_masked | text | NOT NULL | 生成元のマスク済み入力（原文は保存しない） |
| status | varchar(16) | CHECK IN ('draft','pending','approved','running','completed','rejected','failed') | |
| current_revision_id | uuid | FK workflow_revisions NULL（DEFERRABLE） | |
| max_severity | varchar(8) | CHECK IN ('low','medium','high','critical') NULL | 最新検査の最大 severity（表示・承認時のリスク確認用。処理の流れは scan_decision で決まる） |
| lock_version | integer | NOT NULL DEFAULT 0 | 楽観ロック |
| submitted_at | timestamptz | NULL | |
| created_at / updated_at | timestamptz | NOT NULL | |

インデックス：`(organization_id, status)`、`(organization_id, created_by, created_at DESC)`

### 3.6 workflow_revisions（不変）

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK | |
| organization_id / workflow_id | uuid | FK NOT NULL | |
| revision_no | integer | NOT NULL, UNIQUE(workflow_id, revision_no) | 1から単調増加 |
| plan_snapshot | jsonb | NOT NULL | 正規化済み実行計画（[security-design.md §9](security-design.md)） |
| plan_hash | char(64) | NOT NULL | SHA-256（16進小文字） |
| hash_version | smallint | NOT NULL | 正規化仕様のバージョン |
| policy_version | varchar(32) | NOT NULL | 適用した ActionCatalog のバージョン |
| scan_id | uuid | FK security_scans NOT NULL | このリビジョン内容の検査 |
| scan_decision | varchar(8) | CHECK IN ('allow','warn','block') | |
| change_type | varchar(16) | CHECK IN ('ai_generated','user_edit','reopen') | |
| created_by | uuid | FK users NULL | AI生成時はリクエストユーザー |
| created_at | timestamptz | NOT NULL | |

### 3.7 workflow_tasks（現在の作業セット）

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK | |
| organization_id / workflow_id | uuid | FK NOT NULL | |
| position | smallint | NOT NULL, UNIQUE(workflow_id, position) DEFERRABLE | 1..10 |
| title | varchar(100) | NOT NULL | |
| description | varchar(1000) | NOT NULL | |
| action_type | varchar(50) | NOT NULL | ActionCatalog の値のみ |
| steps | jsonb | NOT NULL | 文字列配列（最大10件・各200文字） |
| priority | varchar(8) | CHECK IN ('low','medium','high') | |
| target_data | varchar(500) | NOT NULL | 対象データの説明 |
| impact_summary | varchar(1000) | NOT NULL | 実行による影響 |
| derived_permissions | jsonb | NOT NULL | サーバーが導出した権限（ソート済み配列） |
| ai_claimed_permissions | jsonb | NOT NULL | AI申告（参考・照合用。認可には使わない） |
| policy_decision | varchar(16) | CHECK IN ('allowed','forbidden') | |
| created_at / updated_at | timestamptz | NOT NULL | |

### 3.8 approvals（不変）

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK | |
| organization_id / workflow_id | uuid | FK NOT NULL | |
| workflow_revision_id | uuid | FK NOT NULL, **UNIQUE** | 1リビジョンにつき決定は1件のみ（同時承認対策） |
| plan_hash | char(64) | NOT NULL | 承認時に提示されたハッシュ |
| decision | varchar(8) | CHECK IN ('approved','rejected') | |
| decided_by | uuid | FK users NOT NULL | |
| comment | varchar(1000) | NULL（rejected時は必須：アプリで検証） | |
| acknowledged_risks | boolean | NOT NULL | Medium以上の確認チェック |
| created_at | timestamptz | NOT NULL | |

- トリガー `approvals_forbid_self_approval`：`decided_by = workflows.created_by` の INSERT を拒否（アプリ側検証との二重化）。申請者と承認者は必ず別ユーザーとなる。
- トリガー `approvals_require_admin`：`decided_by` のユーザーが同一組織の有効な `admin` でない INSERT を拒否（auditor・member による承認をDBでも防ぐ）。
- **承認の有効性は保存せず計算する**：
  `decision='approved'` かつ `workflow_revision_id = workflows.current_revision_id` かつ `plan_hash = revision.plan_hash` かつ 当該承認を参照する `workflow_executions` が存在しない。
  → 承認の「無効化」は UPDATE ではなく、新リビジョンの作成によって表現される。

### 3.9 workflow_executions

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK | |
| organization_id / workflow_id | uuid | FK NOT NULL | |
| approval_id | uuid | FK NOT NULL, **UNIQUE** | 承認は1回だけ消費される（二重実行防止） |
| workflow_revision_id | uuid | FK NOT NULL | |
| idempotency_key | varchar(100) | NOT NULL, UNIQUE(organization_id, idempotency_key) | |
| requested_by | uuid | FK users NOT NULL | |
| status | varchar(16) | CHECK IN ('queued','running','completed','failed') | |
| started_at / heartbeat_at / finished_at | timestamptz | NULL | |
| result | jsonb | NULL | 模擬実行結果（マスク済み・長さ上限あり） |
| error_code | varchar(64) | NULL | |
| created_at / updated_at | timestamptz | NOT NULL | |

部分一意インデックス：`UNIQUE (workflow_id) WHERE status IN ('queued','running')` — 1ワークフローの同時実行は1件のみ。

### 3.10 security_scans（不変）

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK | |
| organization_id | uuid | FK NOT NULL | |
| user_id | uuid | FK NULL | |
| target_type | varchar(16) | CHECK IN ('input','output','revision','self_test') | |
| target_id | uuid | NULL | |
| ruleset_version | varchar(32) | NOT NULL | |
| max_severity | varchar(8) | NULL | |
| decision | varchar(8) | CHECK IN ('allow','warn','block') | 全検出の action から算出（severity からは導出しない） |
| block_reason | varchar(32) | NULL | `SECRET_DETECTED` / `INJECTION_HIGH` / `MASK_FAILED` / `CANARY_LEAK` 等 |
| masking_status | varchar(16) | CHECK IN ('not_required','masked','failed') | `failed` の場合 decision は必ず block（fail closed。CHECK制約で強制） |
| findings_count | integer | NOT NULL | |
| duration_ms | integer | NOT NULL | |
| created_at | timestamptz | NOT NULL | |

### 3.11 security_findings

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK | |
| organization_id / scan_id | uuid | FK NOT NULL | |
| category | varchar(24) | CHECK IN ('pii','secret','injection','schema','forbidden_action','permission_mismatch','markup','canary','masking') | |
| rule_id | varchar(64) | NOT NULL | 例 `PII-EMAIL`、`SEC-APIKEY`、`IJ-OVR-001`、`MASK-FAIL` |
| severity | varchar(8) | CHECK IN ('low','medium','high','critical') | 重大度 |
| action | varchar(16) | CHECK IN ('record','mask_continue','warn','block') | 処理動作（severity とは独立に、ルールごとに定義） |
| message | varchar(300) | NOT NULL | 定型文（入力内容を含めない） |
| masked_excerpt | varchar(200) | NULL | **マスク済みテキストからの抜粋のみ**（最大80文字）。category が `secret` / `masking` の場合は常に NULL（周辺文脈も残さない） |
| position_start / position_end | integer | NULL | マスク済みテキスト上の位置 |
| status | varchar(16) | CHECK IN ('open','acknowledged','resolved','false_positive') DEFAULT 'open' | 対策状況 |
| status_note | varchar(500) | NULL | |
| status_changed_by / status_changed_at | uuid / timestamptz | NULL | 変更は監査ログにも記録 |
| created_at / updated_at | timestamptz | NOT NULL | |

インデックス：`(organization_id, status, severity)`、`(organization_id, created_at DESC)`

### 3.12 audit_logs（不変・ハッシュチェーン）

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | bigint | PK, GENERATED ALWAYS AS IDENTITY | チェーン順序 |
| event_id | uuid | UNIQUE NOT NULL | |
| organization_id | uuid | NULL | 未知メールでのログイン失敗などは NULL |
| actor_type | varchar(16) | CHECK IN ('user','system','anonymous') | |
| actor_user_id | uuid | NULL | |
| event_type | varchar(64) | NOT NULL | [security-design.md §16](security-design.md) |
| resource_type / resource_id | varchar(32) / uuid | NULL | |
| result | varchar(8) | CHECK IN ('success','failure','denied') | |
| severity | varchar(8) | NULL | |
| ip_address | inet | NULL | |
| request_id | uuid | NULL | トレースID |
| metadata | jsonb | NOT NULL DEFAULT '{}' | **イベント種別ごとに許可したキーのみ** |
| occurred_at | timestamptz | NOT NULL | |
| prev_hash | char(64) | NOT NULL | 先頭は64桁の0 |
| hash | char(64) | NOT NULL | `SHA-256(prev_hash ‖ 正規化した行内容)` |

インデックス：`(organization_id, occurred_at DESC)`、`(organization_id, event_type, occurred_at DESC)`、`(actor_user_id, occurred_at DESC)`

**チェーンの直列化：** INSERT はトランザクション内で `pg_advisory_xact_lock(<固定キー>)` を取得し、直前行の `hash` を読んでから書き込む（MVPは単一チェーン）。

**トランザクションとの関係：** 状態変更の成功イベントは業務処理と同一トランザクションで記録する（業務がロールバックされればログも残らない＝事実と一致）。認可拒否・検証失敗・例外などの失敗イベントは業務トランザクションの外で記録する（ロールバックで消えないように）。

### 3.13 ai_usage_logs（不変）

| カラム | 型 | 説明 |
|---|---|---|
| id | uuid PK | |
| organization_id / user_id | uuid | |
| analysis_request_id / workflow_id | uuid NULL | |
| provider / model | varchar(32) / varchar(64) | |
| purpose | varchar(24) CHECK IN ('task_generation','self_test') | |
| prompt_tokens / completion_tokens / total_tokens | integer | |
| estimated_cost_micros | bigint | 推定費用（USDの100万分の1単位） |
| latency_ms | integer | |
| status | varchar(16) CHECK IN ('success','error','timeout','rate_limited','budget_blocked','invalid_output') | |
| error_code | varchar(64) NULL | |
| provider_request_id | varchar(128) NULL | |
| created_at | timestamptz | |

プロンプト・応答本文は**保存しない**。

### 3.14 security_test_runs / security_test_results（results は不変）

`security_test_runs`：id, organization_id, triggered_by, status CHECK('queued','running','completed','failed'), total, passed, failed, ruleset_version, policy_version, started_at, finished_at, created_at

`security_test_results`：id, run_id FK, case_id varchar(32)（例 `ST-02`）, category, name, expected varchar(200), actual varchar(200), passed boolean, duration_ms, details jsonb（マスク済み・定型）, created_at

### 3.15 Laravel標準

- `migrations`、`failed_jobs`（ペイロードはIDのみ）。キュー・キャッシュ・セッション・レート制限は Redis。
- Sanctum SPA認証のため `personal_access_tokens` は作成しない。

## 4. DBロールと権限

| ロール | 用途 | 権限 | 認証情報を持つコンテナ |
|---|---|---|---|
| `postgres` | スーパーユーザー。コンテナ初回起動時の初期化スクリプト（ロール・DB作成）のみで使用 | 全権限 | `postgres` |
| `secureflow_owner` | DB・スキーマ所有・マイグレーション専用（`DB_MIGRATOR_*`）。スーパーユーザーではない（`NOSUPERUSER NOCREATEDB NOCREATEROLE`） | DDL | `migrate` のみ |
| `secureflow_app` | アプリ実行時（`DB_*`）。`NOSUPERUSER NOCREATEDB NOCREATEROLE` | 下表のみ。**スキーマへの CREATE 権限なし** | `app` / `worker` / `scheduler` |

### 4.1 初期化（Phase 0）

`docker/postgres/initdb/` の初期化スクリプトで以下を行う。パスワードは環境変数から受け取り、スクリプトに書かない。

1. `secureflow_owner`・`secureflow_app` ロールを作成
2. データベース `secureflow` を owner 所有で作成（テスト用 `secureflow_test` も同様）
3. `REVOKE ALL ON DATABASE ... FROM PUBLIC`、`GRANT CONNECT ... TO secureflow_app`
4. `public` スキーマ：`REVOKE CREATE ON SCHEMA public FROM PUBLIC`、所有者を owner に変更、`GRANT USAGE ON SCHEMA public TO secureflow_app`

**既定権限（DEFAULT PRIVILEGES）は付与しない。** 各マイグレーションで、テーブルごとに必要な権限だけを明示的に `GRANT` する（付与漏れは app からのアクセス失敗＝fail closed になり、テストで検出される）。`migrations` テーブルへの権限は app に与えない。

### 4.2 テーブル権限

| テーブル | secureflow_app の権限 |
|---|---|
| organizations, organization_settings, users, ai_analysis_requests, workflows, workflow_tasks, workflow_executions, security_findings, security_test_runs | SELECT, INSERT, UPDATE（DELETEは workflow_tasks のみ） |
| **audit_logs, approvals, workflow_revisions, security_scans, ai_usage_logs, security_test_results** | **SELECT, INSERT のみ** |

`audit_logs` の IDENTITY 列のシーケンスには `USAGE` のみ付与する。

### 4.3 マイグレーションの実行経路

- マイグレーションは**専用の `migrate` サービス**（Compose の `tools` プロファイル）でのみ実行する：`docker compose run --rm migrate`（内部で `php artisan migrate --database=pgsql_migrator --force`）。
- `pgsql_migrator` 接続の認証情報（`DB_MIGRATOR_*`）は `migrate` サービスにのみ渡す。`app` コンテナで `php artisan migrate` を実行しても app ロールに DDL 権限がないため失敗する。
- テスト時も同様に、スキーマ作成は `pgsql_migrator` 接続、テスト本体のクエリは app ロールの接続で行い、権限不足を見逃さない（[test-strategy.md](test-strategy.md)）。

### 4.4 Phase 0 時点のスキーマ

Phase 0 では業務テーブルを作成しない（Laravel 雛形の既定マイグレーションは Phase 1 の設計に合わないため削除する）。マイグレーション経路とロール分離の検証のみを行う。

## 5. 改変拒否トリガー

追記専用テーブルすべてに以下を設定する（DB権限との二重防御）。

```sql
CREATE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END $$;

CREATE TRIGGER audit_logs_no_update   BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();
```

**残存リスク：** スキーマ所有者・スーパーユーザーはトリガーを無効化できる。ハッシュチェーンで改ざんの「検出」は可能だが、チェーン全体の再計算による偽装は防げない。→ 将来の拡張候補「チェーン先頭ハッシュの外部ストレージ（例：S3 Object Lock）への定期退避」で対処する（[development-roadmap.md](development-roadmap.md)）。

## 6. データ分類と保持

| 分類 | 該当 | 扱い |
|---|---|---|
| 秘密 | パスワード（ハッシュのみ）、APIキー（DBに保存しない） | — |
| マスク済みユーザー内容 | source_input_masked、workflow_tasks本文、plan_snapshot、masked_excerpt、ai_analysis_requests.input_masked | 原文は保存しない。input_masked は完了時NULL化 |
| 運用メタデータ | audit_logs、ai_usage_logs、security_scans | 本文を含めない |

保持期間（方針。MVPでは自動削除は実装しない）：監査ログ1年、スキャン・利用ログ90日。削除手順は追記専用制約と両立する専用メンテナンス手順として将来設計する。

認証・秘密情報（APIキー・トークン・パスワード・秘密鍵）を含む入力は処理を停止するため、マスク済みの形でも業務テーブルには保存されない（`security_findings` にはルールIDと位置のみ記録）。

**注意：** マスキングは検出できた情報にしか適用されない。氏名・住所など MVP で十分に検出できない情報が、マスク済みテキストに残っている可能性がある（[security-design.md §4](security-design.md)）。
