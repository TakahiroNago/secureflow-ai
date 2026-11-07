# SecureFlow AI — データベース設計書

- 版：v1.11（2026-11-07）
- 状態：確定（v1.11：工程2-8 の ai_usage_logs を反映。v1.10：工程2-4 の出力検証とプロンプト構築を反映。v1.9：工程2-3 の入力検査の組み込みを反映。v1.8：工程1-6 の分析の依頼とキューのテーブルを反映。v1.7：工程1-5 のワークフローのテーブルの判断を反映。v1.6：工程1-3 の監査ログハッシュチェーンを反映。v1.5：テスト専用 app ロールを追加。v1.4：テスト専用 owner ロールとコマンド制限を追加。v1.3：工程1-1 の設計レビューを反映。v1.2：列挙列の NOT NULL 方針を明記。v1.1：Q-D13・Q-PII・D11・Phase 0 追加条件を反映）
- DBMS：PostgreSQL 18.6（インフラ要件。`compose.yaml` でタグを固定する）

---

## 1. 設計方針

1. **主キーは UUIDv7**（`audit_logs` のみ連番 + `event_id` UUID）。**Laravel の `HasUuids` で生成し、DB の `DEFAULT` では生成しない**（保存直後に ID を参照できるようにするため）。ID を省略した生SQLの INSERT は `NOT NULL` 制約で拒否される。UUIDは列挙耐性のための補助であり、**認可の代わりにしない**（[security-design.md §13](security-design.md)）。
2. **全業務テーブルに `organization_id`** を持たせ、組織スコープでのデータ分離を徹底する。
3. **履歴系テーブルは追記専用**（UPDATE/DELETE をDB権限とトリガーの両方で拒否）。
4. **原文・秘密情報を保存しない。** ユーザー入力由来の本文はマスキング後のもののみ。
5. 時刻はすべて `timestamptz`（UTC保存、表示時にJST変換）。
6. 列挙値は `varchar` + `CHECK` 制約（PostgreSQLのENUM型は変更が重いため不採用）。`CHECK` は NULL を通すため、列挙列は **`NULL` と明記したものを除き `NOT NULL`** とする。
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
audit_logs（全イベント・追記専用・ハッシュチェーン）─ audit_chain_heads（チェーンごとの最新位置）
ai_usage_logs（AI呼び出し記録・追記専用）
security_test_runs 1─* security_test_results
```

**タスクとリビジョンの関係：**
`workflow_tasks` は現在の編集用の作業セット（可変）。編集のたびに正規化スナップショットを `workflow_revisions.plan_snapshot` に**不変レコード**として保存し、そのハッシュを承認対象とする。**模擬実行は承認されたリビジョンのスナップショットのみを入力とする**（可変テーブルを実行に使わない）。実行直前には現在のタスクから再計算したハッシュと承認ハッシュを照合し、乖離を検出する。

## 3. テーブル定義

### 3.1 organizations

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK, CHECK (`id <> '00000000-0000-0000-0000-000000000000'`) | NIL UUID はシステムチェーンの識別子のため、組織 ID に使えない（§3.12.1。工程1-3で追加） |
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
| password | varchar(255) | NOT NULL | Argon2id ハッシュ（ハッシュ設定は工程1-2） |
| role | varchar(16) | NOT NULL, CHECK IN ('admin','member','auditor') | |
| is_active | boolean | NOT NULL DEFAULT true | |
| failed_login_count | smallint | NOT NULL DEFAULT 0 | |
| locked_until | timestamptz | NULL | アカウントロック |
| last_login_at / password_changed_at | timestamptz | NULL | |
| password_change_key_hash | char(64) | NULL, CHECK（小文字16進64桁） | 直近のパスワード変更の `Idempotency-Key` の HMAC-SHA256。**平文を保存しない。** 変更と同じトランザクションで保存し、応答に含めない（工程1-3で追加。[security-design.md §16.5.5](security-design.md)） |
| password_change_previous_hash | varchar(255) | NULL | 変更前の Argon2id ハッシュ。再試行の `current_password` の照合にのみ使う。**期限（暫定15分）は API が `password_changed_at` で必ず検証する。`scheduler` は期限切れの値を NULL にする後片付けのみを担当する。** 現在のパスワードハッシュと同じ秘密として扱い、応答、ログ、監査ログ、例外に出さない（工程1-3で追加。[security-design.md §16.5.5](security-design.md)） |
| created_at / updated_at | timestamptz | NOT NULL | |

インデックス：`(organization_id)`

セッションは Redis に保存する（`sessions` テーブルは使用しない）。

### 3.4 ai_analysis_requests

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | uuid | PK | |
| organization_id / user_id | uuid | FK NOT NULL | |
| status | varchar(16) | CHECK IN ('queued','processing','succeeded','blocked','failed') | |
| input_masked | text | NULL | マスク済み入力。**処理完了時に NULL 化**（CHECK で強制：`queued`・`processing` 以外は NULL）。入力検査で block となった場合はレコードを作成しない（スキャン結果のみ保存） |
| input_char_count | integer | NOT NULL | |
| input_scan_id | uuid | NULL、複合 FK。**新規行は必須**（CHECK NOT VALID：工程2-3 より前の行は変更しない） | |
| output_scan_id | uuid | NULL、複合 FK。`succeeded` の新規行は必須（CHECK NOT VALID） | |
| workflow_id | uuid | FK NULL, UNIQUE, CHECK（`status = 'succeeded'` と同時に NOT NULL） | 成功時に設定 |
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
| source_input_masked | text | NULL（工程1-6で変更） | 生成元のマスク済み入力（原文は保存しない）。**NULL は保存していないことを表す**（工程2-3 より前の行） |
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
| scan_id | uuid | NULL、複合 FK。**新規行は必須**（CHECK NOT VALID：工程2-3 より前の行は変更しない） | このリビジョン内容の検査。**NULL は未検査を意味する。** |
| scan_decision | varchar(8) | NULL, CHECK IN ('allow','warn','block')、CHECK（`scan_id` と同時に NULL または NOT NULL） | **NULL を allow として扱わない。** 工程2-5・2-6 は未検査のリビジョンの提出・承認・実行を拒否する。検査済みに見えるダミーの検査結果は作らない。外部キーに含めるため、検査の判定と異なる値は保存できない |
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
| ai_claimed_permissions | jsonb | NOT NULL | AI申告（参考・照合用。認可には使わない）。**他の項目と同じく検査してマスクした値**（工程2-4）。工程2-3 より前と工程2-3 の行は未検査である |
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

### 3.9.1 組織とワークフローをまたぐ参照の防止（工程1-5）

§3.5〜§3.9 の外部キーは複合とし、アプリケーションの不具合があっても別の組織やワークフローの行を指せないようにする。このために `users` に `UNIQUE (organization_id, id)` を追加する。

| 外部キー | 防ぐこと |
|---|---|
| 子テーブルの `(organization_id, workflow_id)` → `workflows` | 別の組織のワークフローへの所属 |
| `(organization_id, created_by / decided_by / requested_by)` → `users` | 別の組織のユーザーの記録 |
| `workflows (id, current_revision_id)` → `workflow_revisions (workflow_id, id)`（DEFERRABLE） | 別のワークフローのリビジョンの指定 |
| `approvals`・`workflow_executions` の `(workflow_id, workflow_revision_id)` → `workflow_revisions` | 別のワークフローのリビジョンの承認・実行 |
| `workflow_executions (approval_id, workflow_revision_id)` → `approvals (id, workflow_revision_id)` | 別のリビジョンの承認による実行 |

`approvals_require_admin` は対象のユーザー行を `FOR SHARE` でロックし、確認からコミットまでの間のロール変更を防ぐ。`down` は `workflow_revisions`・`approvals` に行がある場合に中断する。

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
| block_reason | varchar(32) | NULL、CHECK（`decision = block` と同時に NOT NULL） | `SECRET_DETECTED` / `INJECTION_HIGH` / `MASK_FAILED` / `CANARY_LEAK` 等 |
| masking_status | varchar(16) | CHECK IN ('not_required','masked','failed') | `failed` の場合 decision は必ず block（fail closed。CHECK制約で強制） |
| findings_count | integer | NOT NULL | 実際の検出数。`security_findings` に保存するのは1回の検査につき最大100行（処理を止める検出を優先） |
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
| masked_excerpt | varchar(200) | NULL | **マスク済みテキストからの抜粋のみ**（最大80文字。CHECK で強制）。category が `secret` / `masking` の場合、`action` が `block` の場合は常に NULL（CHECK で強制。周辺文脈も残さない）。同じ検査に `block` があれば全検出で NULL、確認（scan-preview）でも NULL とする（アプリで保証） |
| field_path | varchar(64) | NULL | 検出した項目（`tasks.2.steps.1`、`title`）。単一の入力では NULL。工程2-3 で追加 |
| position_start / position_end | integer | NULL | `block` では入力された文の位置（マスク済みの文がないため）、それ以外ではマスク済みテキスト上の位置 |
| status | varchar(16) | CHECK IN ('open','acknowledged','resolved','false_positive') DEFAULT 'open' | 対策状況 |
| status_note | varchar(500) | NULL | |
| status_changed_by / status_changed_at | uuid / timestamptz | NULL | 変更は監査ログにも記録 |
| created_at / updated_at | timestamptz | NOT NULL | |

インデックス：`(organization_id, status, severity)`、`(organization_id, created_at DESC)`

**工程2-3 の決定：** 新規行のみ検査を必須とするため、`workflow_revisions`・`ai_analysis_requests` の必須の制約は `NOT VALID` とする。工程2-3 より前の行は未検査のまま変更しない。`security_scans` は改変拒否（トリガーと権限）で、行がある間は `down` を中断する。**`ai_analysis_requests` の `NOT VALID` の制約は行の更新にも適用されるため、適用の前に `queued`・`processing` の行がないことを確認する。**

### 3.12 audit_logs（不変・ハッシュチェーン）

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| id | bigint | PK, GENERATED ALWAYS AS IDENTITY | 行の識別子。**チェーン順序ではない**（下記） |
| event_id | uuid | UNIQUE NOT NULL | |
| organization_id | uuid | NULL, CHECK (NIL UUID 以外) | 組織に属さないイベント（未知メールでのログイン失敗など）は NULL |
| chain_id | uuid | NOT NULL, GENERATED ALWAYS AS (`COALESCE(organization_id, NIL UUID)`) STORED | チェーンの識別子。組織チェーンは組織 ID、システムチェーンは NIL UUID。**アプリから指定できない** |
| chain_seq | bigint | NOT NULL, CHECK (>= 1) | チェーン内の順序。1から連番で欠番なし。**チェーン順序はこの列のみで決まる** |
| actor_type | varchar(16) | NOT NULL, CHECK IN ('user','system','anonymous') | |
| actor_user_id | uuid | NULL, CHECK（`actor_type = 'user'` のときのみ NOT NULL） | |
| event_type | varchar(64) | NOT NULL | [security-design.md §16](security-design.md) |
| resource_type / resource_id | varchar(32) / uuid | NULL | |
| result | varchar(8) | NOT NULL, CHECK IN ('success','failure','denied') | |
| severity | varchar(8) | NULL, CHECK IN ('low','medium','high','critical') | |
| ip_address | inet | NULL, CHECK（IPv4 は `/32`、IPv6 は `/128` のみ） | ネットワーク表記を許すと、正規形（§3.12.3）で表せない差が生じるため |
| request_id | uuid | NULL | トレースID |
| metadata | jsonb | NOT NULL DEFAULT '{}', CHECK (`jsonb_typeof = 'object'`) | **イベント種別ごとに許可したキーのみ**。形式は §3.12.3 |
| occurred_at | timestamptz | NOT NULL | `audit_append()` がロック取得後の `clock_timestamp()` で設定する。**アプリから指定できない。順序の根拠にしない** |
| hash_version | smallint | NOT NULL, CHECK (= 1) | ハッシュ仕様の版（§3.12.3）。仕様を追加するときに CHECK を広げる |
| prev_hash | char(64) | NOT NULL, CHECK（小文字16進64桁） | チェーンの先頭は64桁の0 |
| hash | char(64) | NOT NULL, CHECK（小文字16進64桁） | §3.12.3 の正規形の SHA-256 |

制約：`UNIQUE (chain_id, chain_seq)`

インデックス：`(organization_id, occurred_at DESC)`、`(organization_id, event_type, occurred_at DESC)`、`(actor_user_id, occurred_at DESC)`

**外部キーは設定しない（工程1-1と同じ）。** 監査ログは参照先の変更に影響されず残す必要があるため、組織とユーザーの存在は `audit_append()` が確認する。

**`id` とチェーン順序は別物：** IDENTITY の `id` は採番順であり、トランザクションのコミット順序を保証しない（先に採番した行が後からコミットされることがある）。**`id` の順序をハッシュチェーンの順序として扱わない。** `id` はハッシュの計算にも含めない。

**開発用DBの `audit_logs_id_seq` の記録：** 2026-11-04 の確認作業で開発用DBに INSERT を試して ROLLBACK した際、シーケンスが `1,false` から `5,true` に進んだ。PostgreSQL のシーケンスは ROLLBACK で戻らない仕様による。**現状を維持し、`setval` 等で戻さない。** `audit_logs` は0行のままで、次に採番される `id` は 6 になる。`id` の欠番はチェーンの検証に影響しない。今後、シーケンス・DDL・INSERT・ROLLBACK を伴う検証は使い捨てのDBでのみ行う。

**トランザクションとの関係：** 状態変更の成功イベントは原則として業務処理と同一トランザクションで記録する（業務がロールバックされればログも残らない＝事実と一致）。認可拒否・検証失敗・例外などの失敗イベントは、**業務トランザクションのロールバックまたはコミットの後に**記録する（ロールバックで消えないように）。認証イベントの個別の扱いは [security-design.md §16.5](security-design.md) に定める。

#### 3.12.1 チェーンの単位

| チェーン | `chain_id` | 対象 | 参照経路 |
|---|---|---|---|
| 組織チェーン | 組織の ID | 組織に属するイベント | 組織の admin / auditor（API、工程2-7）、運用者（コマンド） |
| システムチェーン | NIL UUID（`00000000-0000-0000-0000-000000000000`） | 組織に属さないイベント | **運用者（コマンド）のみ。** 組織の admin / auditor からは参照できない |

- NIL UUID は組織 ID として使えない。`organizations` と `audit_logs.organization_id` の CHECK、`audit_append()` の引数検証で三重に防ぐ。システムチェーンへの記録は `p_organization_id` を NULL にした場合のみ行われる。
- API のクエリは常に `organization_id = 認証ユーザーの組織` で絞り込み、`chain_id` を入力として受け取らない。システムチェーンの行は `organization_id` が NULL のため、この条件に一致しない。
- app ロールは技術的には全行を SELECT できる（既存の組織スコープと同じくアプリ層で分離する。RLS は拡張候補）。

#### 3.12.2 audit_chain_heads

| カラム | 型 | 制約 | 説明 |
|---|---|---|---|
| chain_id | uuid | PK | |
| last_seq | bigint | NOT NULL, CHECK (>= 0) | |
| last_hash | char(64) | NOT NULL, CHECK（小文字16進64桁） | |
| updated_at | timestamptz | NOT NULL | |

- 行は該当チェーンの最初の記録時に `audit_append()` が作成する（`last_seq = 0`、`last_hash` は64桁の0から開始）。
- 所有者の誤操作に対する防御として、トリガーで DELETE・TRUNCATE と、`last_seq` を1ずつ増やす以外の UPDATE を拒否する。スーパーユーザーや所有者はトリガーを無効化できるため、悪意ある所有者への防御にはならない（§5）。

#### 3.12.3 ハッシュの正規形（`secureflow.audit.v1`）

PostgreSQL の `audit_append()` と PHP の検証器は、次の仕様を別々に実装する。

```
hash      = 小文字16進( SHA-256( UTF-8( canonical ) ) )
canonical = "secureflow.audit.v1|" + 16個のフィールドを "|" で連結
field     = NULL なら "-"、それ以外は "<値のUTF-8バイト数>:<値>"
```

| 順 | フィールド | 文字列への変換 |
|---|---|---|
| 1 | chain_id | UUID の小文字ハイフン区切り（36文字） |
| 2 | chain_seq | 10進数 |
| 3 | prev_hash | 小文字16進64桁 |
| 4〜5 | event_id、organization_id | UUID の小文字ハイフン区切り |
| 6〜8 | actor_type、actor_user_id、event_type | そのまま / UUID / そのまま |
| 9〜10 | resource_type、resource_id | そのまま / UUID |
| 11〜12 | result、severity | そのまま |
| 13 | ip_address | PostgreSQL の `host()` の結果（`/32`・`/128` を付けない。IPv6 は小文字の短縮形。例：`2001:db8::1`）。IPv4 射影アドレスは変換せず、受け取った形のまま（例：`::ffff:192.0.2.1`） |
| 14 | request_id | UUID の小文字ハイフン区切り |
| 15 | metadata | 下記の正規 JSON |
| 16 | occurred_at | UTC、マイクロ秒6桁固定：`YYYY-MM-DDTHH:MM:SS.ffffffZ`（例：`2026-11-04T03:34:56.000000Z`） |

- **長さの単位は UTF-8 のバイト数とする。** Unicode 正規化は行わない（入力のコードポイントをそのまま扱う）。DB のエンコーディングは UTF8 に限定し、マイグレーションで確認する。
- **NULL と空文字は別の値である。** NULL は `-`、空文字は `0:`、1文字のハイフンは `1:-` となり、衝突しない。
- `id` は含めない。`hash_version` は先頭の `secureflow.audit.v1` で表す。

**metadata の形式：** `audit_append()` は次を満たさない値を拒否する。

| 項目 | 仕様 |
|---|---|
| 階層 | オブジェクト1階層のみ（配列・入れ子は不可） |
| キー | `^[a-z][a-z0-9_]{0,63}$`、最大16個 |
| 値の型 | 文字列、真偽値、整数のみ（`null`・小数は不可） |
| 整数の範囲 | ±(2^53 − 1)。`1.0` のように小数点を含む表記は不可 |
| 文字列 | UTF-8 で1024バイト以下。制御文字（U+0001〜U+001F、U+007F）は不可 |
| 全体 | 正規 JSON で4096バイト以下。値がない場合は `{}` |

**正規 JSON：** `jsonb::text` の表記に合わせる。キーは「UTF-8 バイト数の昇順、同じ長さならバイト順」、区切りは `, ` と `: `。エスケープするのは `"` と `\` のみで、`/` と非 ASCII（U+2028・U+2029 を含む）はそのまま出力する。

PHP では `json_encode` に `JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_LINE_TERMINATORS` を指定する（`JSON_UNESCAPED_LINE_TERMINATORS` がないと U+2028 がエスケープされ、ハッシュが一致しない）。PHP の空配列は `[]` になるため、空の metadata は `{}` として扱う。検証器は DB の表記をそのまま使わず、デコードした値から正規 JSON を組み立てる（PostgreSQL の表記が変わった場合も、過去の行の検証が影響を受けないようにするため）。`host()` と `occurred_at` の文字列は検証器が SQL で取得する。

**固定テストベクトル：** `backend/tests/Fixtures/audit-hash-vectors.json` に置き、PHP と PostgreSQL の両方のテストで同じファイルを読む。すべて PostgreSQL 18.6、Python、PHP 8.4.27 の別々の計算で一致を確認済み（使い捨ての環境。正規形の計算の試作であり、実装の確認は工程1-3の AUDIT-HASH-01 で行う）。一致しない場合は、値を合わせて書き換えず、原因を報告する。特記のないものの occurred_at は `2026-11-04T03:34:56.789012Z`、Z は64桁の0、N は NIL UUID とする。

| 検証の観点 | ベクトル | 実装の誤りで起きること |
|---|---|---|
| NULL と空文字、`-` の区別 | V3-a、V3-b、V3-c | 3つのハッシュが同じになる |
| Unicode を正規化しない | V5-a（NFC）、V5-b（NFD） | 2つのハッシュが同じになる |
| 長さがバイト数である | V5-c（2文字・6バイト）、V5-d（1文字・4バイト）、V2 | `mb_strlen`・`char_length` を使うと `15:`・`13:` にならない |
| 時刻の固定表記 | V6-a（小数なしの入力）、V6-b（1マイクロ秒）、V6-c（年末） | 桁の省略、ミリ秒への丸め、ローカル時刻 |
| JSONB の正規化 | V4（順序・エスケープ・U+2028・整数の上限・真偽値）、V7（重複キー、短いキーが先）、V3-a（`{}`） | 辞書順の並び替え、`[]`、U+2028 のエスケープ |

| ID | 入力（順に 1〜15。16 は共通の occurred_at） | SHA-256 |
|---|---|---|
| V1 組織チェーンの先頭 | `01890000-0000-7000-8000-000000000001`、`1`、Z、`…0000000000e1`、`…000000000001`、`user`、`…0000000000a1`、`auth.login`、NULL、NULL、`success`、NULL、`203.0.113.1`、`…0000000000d1`、`{"a": 1, "reason_code": "ok"}` | `0c402d0ec526b37510b5dfe13fdd6b5922b9359130e0ddab0fb754cc2f304ced` |
| V2 システムチェーン、IPv6、マルチバイト | N、`2`、`ab54a98ceb1f0ad2c1bbff1dd3c0b6d7b6e9d0f1c2a3b4c5d6e7f8091a2b3c4d`、`…0000000000e2`、NULL、`anonymous`、NULL、`auth.login_failed`、NULL、NULL、`failure`、`low`、`2001:db8::1`、NULL、`{"ok": true, "reason_code": "認証"}` | `25275350129eb68b2684b305c5b081d28d30f6ffe71c5f07134985fd2ce50807` |
| V3-a resource_type が NULL | N、`1`、Z、`…0000000000e3`、NULL、`system`、NULL、`audit.test`、**NULL**、NULL、`success`、NULL、NULL、NULL、`{}` | `de5dc1213c87c491294f35bdd4456d5e75f24ee09cba38b3bc69dda531922a02` |
| V3-b resource_type が空文字 | V3-a の第9項目を `''` に変更 | `5f2f49b503f86b28ccf7bbd87537949efd20efd64dcb4cb960de4cd82ac274c9` |
| V3-c resource_type が `-` | V3-a の第9項目を `-` に変更 | `b465f39d1def92bd176fa9abf7b236c5606ba15909e10a871c4b3547107b5152` |
| V4 正規 JSON のみ | `{"zz":-5,"ok":false,"reason_code":"a\"b\\c/d é 認証 😀","aa":9007199254740991,"line":"x y"}` を正規化した UTF-8 バイト列。結果は `{"aa": 9007199254740991, "ok": false, "zz": -5, "line": "x<U+2028>y", "reason_code": "a\"b\\c/d é 認証 😀"}`（é は U+00E9） | `98943942d3cc3cb39fa7e704e2ecb811a1a2b53f32b8296b99e1cb13c5c5e572` |
| V5-a NFC | V3-a の第15項目を `{"s": "<U+00E9>"}` に変更（フィールドは `11:` で始まる） | `22ccb86eb6d80a079155f11038a9c55d6c86227f22645e0b2b3238c608c08157` |
| V5-b NFD | V3-a の第15項目を `{"s": "e<U+0301>"}` に変更（`12:`） | `461ee0a81494283fe02b3537548eeb9a53df06cd49aa4145e0ff76f67628f1d7` |
| V5-c 2文字・6バイト | V3-a の第15項目を `{"s": "認証"}` に変更（`15:`） | `df9a0413595c7e350fcb6dae79e56de00f610963cb14a1d755eef6a90221405c` |
| V5-d 1文字・4バイト | V3-a の第15項目を `{"s": "<U+1F600>"}` に変更（`13:`） | `fd492e5fde083020f4f2c5f1a1748e1d470f41d37216a5ab23f137a4fa2634c4` |
| V6-a 小数なし | V3-a の occurred_at を `2026-11-04T03:34:56.000000Z` に変更（入力は `2026-11-04 12:34:56+09:00`） | `0d2051aa7c74678b7f7e3a5da3b3bed38b9f205b56fbd06f6cd6dcbe33c26381` |
| V6-b 1マイクロ秒 | V3-a の occurred_at を `2026-11-04T03:34:56.000001Z` に変更 | `3202dfdc6bffed3f4668b708af347534b1f2bbcdf219b816fdf9e60f1b3d4c63` |
| V6-c 年末 | V3-a の occurred_at を `2026-12-31T23:59:59.999999Z` に変更 | `6bb33ebf344433dc69c5827957e75492a87037ad6b85f0d10a2665873c79d951` |
| V7 重複キーと順序 | V3-a の第15項目を、入力 `{"b":1,"aa":"x","aa":"y"}` の正規形 `{"b": 1, "aa": "y"}` に変更 | `2bc8c2b30cd935937c18664b7375be3bf83a1533cef6d39f2db4923e61c8a74b` |

（`…` は `01890000-0000-7000-8000-` の省略）

**版の管理と PostgreSQL の更新：**

- 公開後の仕様は変更しない。変更が必要な場合は `secureflow.audit.v2` を追加し、**過去の行を再計算しない**。新しい行だけ `hash_version = 2` とし、検証器は行の版で計算方法を切り替える。チェーン内で版が小さくなる行は改ざんとして扱う。
- PostgreSQL のメジャー更新の前に、使い捨てのDBで新版へ復元し、固定テストベクトルと `audit:verify --all` が成功することを確認する。`jsonb::text`・`host()`・`to_char()` の表記が変わっていた場合は `audit_append()` を修正してから更新する。

#### 3.12.4 追記関数 `audit_append()`

**`audit_logs` への追記はこの関数のみで行う。** アプリから `chain_seq`・`prev_hash`・`hash`・`occurred_at` を指定する手段を設けない。

```sql
public.audit_append(
  p_event_id uuid, p_organization_id uuid, p_actor_type text, p_actor_user_id uuid,
  p_event_type text, p_resource_type text, p_resource_id uuid, p_result text,
  p_severity text, p_ip_address inet, p_request_id uuid, p_metadata jsonb
) RETURNS bigint  -- 記録した chain_seq
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET lock_timeout = '2s'
```

処理：① 引数を検証　② `audit_chain_heads` の行がなければ作成（`ON CONFLICT DO NOTHING`）　③ 該当行を `SELECT ... FOR UPDATE`　④ ロック取得後に `clock_timestamp()` を取得　⑤ ハッシュを計算　⑥ `audit_logs` に INSERT　⑦ ヘッドを UPDATE。ヘッドのロックはトランザクションの終了まで保持される。

**`audit.availability_checked` の重複：** この種別に限り、⑥を例外ブロックで囲む。`unique_violation` のとき、`GET STACKED DIAGNOSTICS` の `CONSTRAINT_NAME` が `event_id` の制約名（`audit_logs_event_id_key`）と完全に一致し、既存の行の `event_type`、`chain_id`、`metadata->>'outage_id'` がすべて一致した場合のみ、専用の SQLSTATE `SF001` を返す。それ以外は元のエラーを再送出する。文字列を解析しない（[security-design.md §16.5.1](security-design.md)）。

| 要件 | 内容 | 確認方法（AUDIT-FN-01・AUDIT-PRIV-01） |
|---|---|---|
| 所有者 | 開発用DBは `secureflow_owner`、テスト用DBは `secureflow_test_owner`（それぞれのDBのマイグレーション実行ロール）。**app ロールに所有者ロールのメンバーシップを与えない** | `pg_proc.proowner`、`pg_has_role(app, owner, 'MEMBER')` が false |
| SECURITY DEFINER | `audit_append()` のみ。正規形と metadata 検証の補助関数は SECURITY INVOKER | `pg_proc.prosecdef` |
| EXECUTE | `PUBLIC` から REVOKE し、接続設定の app ロールにのみ GRANT する。`CREATE OR REPLACE` は ACL を維持するが、適用のたびに REVOKE / GRANT を明示する。補助関数の EXECUTE は app に与えない（検証器は PHP で独立に計算するため不要） | `pg_proc.proacl`、`has_function_privilege()` |
| 固定 `search_path` | `pg_catalog, pg_temp` に固定する（`pg_temp` を明示的に最後に置き、一時オブジェクトによる差し替えを防ぐ）。`public` を含めない。呼び出し元の設定に依存しない | `pg_proc.proconfig`、一時スキーマに同名のオブジェクトを作っても呼ばれないこと |
| スキーマ修飾 | 関数内のテーブル・関数はすべて `public.` でスキーマ修飾する（`pg_catalog` の組み込み関数を除く） | `pg_proc.prosrc` の確認、`search_path` が固定された状態でのテストの成功 |
| 動的SQL禁止 | `EXECUTE` 文と `format()` による SQL の組み立てを使わない。`audit_append()` と補助関数のすべてに適用する | `pg_proc.prosrc` に `EXECUTE`・`format(` がないこと |
| エラー | 引数の検証エラーは `22023`。メッセージに引数の値を含めない | エラーメッセージの確認 |

**引数の検証：**

| 引数 | 検証 |
|---|---|
| `p_event_id`、`p_actor_type`、`p_event_type`、`p_result`、`p_metadata` | NULL を拒否 |
| `p_event_type` | `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`、64文字以下。**許可リストはアプリの `AuditEventType` で管理する**（種類の追加のたびにDB関数を変更しないため） |
| `p_organization_id` | NIL UUID を拒否。NULL 以外は `organizations` に存在すること |
| `p_actor_type`、`p_actor_user_id` | `user` のとき `p_actor_user_id` は必須で、**`users` に存在し、`p_organization_id` と同じ組織に属すること**。`system`・`anonymous` のときは NULL |
| `p_resource_type` | NULL または `^[a-z][a-z0-9_]{0,31}$`（空文字を拒否）。`p_resource_id` は `p_resource_type` があるときのみ指定できる |
| `p_result`、`p_severity` | 列の CHECK と同じ列挙値 |
| `p_ip_address` | `/32`・`/128` 以外を拒否 |
| `p_metadata` | §3.12.3 の形式 |

**`actor_user_id` の信頼性の限界：** DB が確認できるのは「そのユーザーが同じ組織に属すること」だけで、**そのユーザーが実際にログインした本人であることを独立に証明できない。** app ロールを奪取した攻撃者は、同じ組織の別のユーザーを actor として記録できる。アプリでは、`AuditLogger` の公開 API が actor の ID を引数に取らず、認証済みのサーバー側コンテキストから actor を決定する（[security-design.md §16.5](security-design.md)）。この残存リスクは [threat-model.md R-11](threat-model.md) に記録する。

**トランザクションの判定：** PostgreSQL の関数は必ずトランザクションの中で実行されるため、**`audit_append()` は業務トランザクションの内外を判定できない。** 判定はアプリ側で、Laravel のトランザクションレベルにより行う（[security-design.md §16.5](security-design.md)）。

**ロック：**

- 同じチェーンの書き込みは直列化され、別のチェーンは影響を受けない。待ちが2秒（暫定値。負荷試験で調整し、変更は `ALTER FUNCTION` のマイグレーションで行う）を超えると `55P03`（`lock_not_available`）で失敗する。タイムアウトの全体は [security-design.md §16.5.6](security-design.md) に定める。
- 業務トランザクションで記録する場合は、ヘッドのロックが他の記録を止めないよう、**トランザクションの最後に記録する**。**ヘッドのロックを保持したまま外部通信を行わない**（パスワード変更の Redis への書き込みは、ヘッドのロックの取得前に行う。[security-design.md §16.5.5](security-design.md)）。
- **1つのトランザクションで複数のチェーンに記録しない。** 順序が逆の2つのトランザクションでデッドロックになるため（DB が一方を中断し、チェーン自体は壊れないことを試作で確認済み）、`AuditLogger` で拒否する。

#### 3.12.5 検証

PHP の検証器（`AuditChainVerifier`）は `audit_append()` の補助関数を使わず、§3.12.3 に従って独立に再計算する。

- `REPEATABLE READ READ ONLY` のトランザクションで、1チェーンを同じスナップショットから読む。ヘッドをロックしないため、実行中の記録を止めない。
- `chain_seq` の順に読み（`id` の順には読まない）、メモリに全行を保持しない。

| 理由コード | 検出する状態 |
|---|---|
| `SEQUENCE_GAP` | `chain_seq` が1からの連番でない（途中の行の削除） |
| `PREV_HASH_MISMATCH` | `prev_hash` が前の行の `hash` と一致しない |
| `HASH_MISMATCH` | 再計算したハッシュが `hash` と一致しない（行の変更） |
| `CHAIN_ID_MISMATCH` | `chain_id` が `organization_id` から導かれる値と一致しない |
| `NON_CANONICAL_VALUE` | `ip_address` のマスク長、metadata の形式など、§3.12.3 の正規形で表せない値 |
| `UNSUPPORTED_VERSION` | 未知の `hash_version`、または版が小さくなる行 |
| `HEAD_MISMATCH` | ヘッドの `last_seq`・`last_hash` が最後の行と一致しない（末尾の行の削除） |
| `HEAD_MISSING` | 行があるのにヘッドがない |
| `ANCHOR_MISMATCH` | 外部保管したヘッド（`audit:head` の出力）と、その `chain_seq` の行のハッシュが一致しない、またはその行がない（チェーンが丸ごとない場合を含む） |

**検証で検出できない改ざん：** 末尾の行の削除とヘッドの巻き戻しを同時に行った場合、および所有者権限でチェーン全体を再計算した場合、**DB の中の情報だけでは検出できない**（試作で確認済み）。これを検出できるのは、改ざんより前に `audit:head` の出力をDBの外へ保管している場合に限られ、**検出できるのはその保管時点までの範囲である**（[security-design.md §16.3](security-design.md)、[threat-model.md R-03](threat-model.md)）。

### 3.13 ai_usage_logs（不変）

| カラム | 型 | 説明 |
|---|---|---|
| id | uuid PK | |
| organization_id / user_id | uuid | |
| analysis_request_id | uuid NULL | 工程2-8。ワークフローは分析から辿れるため `workflow_id` は持たない |
| provider / model | varchar(32) / varchar(64) | |
| purpose | varchar(24) CHECK IN ('task_generation','self_test') | |
| prompt_tokens / completion_tokens / total_tokens | integer | |
| estimated_cost_micros | bigint | 推定費用（USDの100万分の1単位） |
| latency_ms | integer | |
| status | varchar(16) CHECK IN ('success','error','timeout','rate_limited','budget_blocked','invalid_output') | |
| error_code | varchar(64) NULL | |
| provider_request_id | varchar(128) NULL | |
| created_at | timestamptz | |

プロンプト・応答本文は**保存しない**。トークン数と推定費用は、数えていない場合（モック、上限による拒否、タイムアウト）は NULL で、0 と区別する。`model` も NULL を許す。

### 3.14 security_test_runs / security_test_results（results は不変）

`security_test_runs`：id, organization_id, triggered_by, status CHECK('queued','running','completed','failed'), total, passed, failed, ruleset_version, policy_version, started_at, finished_at, created_at

`security_test_results`：id, run_id FK, case_id varchar(32)（例 `ST-02`）, category, name, expected varchar(200), actual varchar(200), passed boolean, duration_ms, details jsonb（マスク済み・定型）, created_at

### 3.15 Laravel標準

- `migrations`、`jobs`、`failed_jobs`（ペイロードはIDのみ。工程1-6で追加）。**キューは DB（[architecture.md §10](architecture.md)）。** キャッシュ・セッション・レート制限は Redis。
- Sanctum SPA認証のため `personal_access_tokens` は作成しない。

## 4. DBロールと権限

| ロール | 用途 | 権限 | 認証情報を持つコンテナ |
|---|---|---|---|
| `postgres` | スーパーユーザー。コンテナ初回起動時の初期化スクリプト（ロール・DB作成）のみで使用 | 全権限 | `postgres` |
| `secureflow_owner` | 開発用DB・スキーマ所有・マイグレーション専用（`DB_MIGRATOR_*`）。スーパーユーザーではない（`NOSUPERUSER NOCREATEDB NOCREATEROLE`）。テスト用DBには接続できない | DDL | `migrate` のみ |
| `secureflow_test_owner` | テスト用DB・スキーマ所有。スキーマ初期化とマイグレーション専用（`DB_TEST_MIGRATOR_*`）。`NOSUPERUSER NOCREATEDB NOCREATEROLE`。**開発用DBには接続できない** | テスト用DBの DDL のみ | `test` のみ |
| `secureflow_app` | アプリ実行時（`DB_*`）。`NOSUPERUSER NOCREATEDB NOCREATEROLE`。**テスト用DBには接続できない** | 下表のみ。**スキーマへの CREATE 権限なし** | `app` / `worker` / `scheduler` |
| `secureflow_test_app` | テスト本体の実行専用（`DB_TEST_USERNAME` / `DB_TEST_PASSWORD`）。`NOSUPERUSER NOCREATEDB NOCREATEROLE`。**開発用DBには接続できない** | テスト用DBで下表のみ（`secureflow_app` と同じ権限をマイグレーションが付与） | `test` のみ |

### 4.1 初期化（Phase 0）

`docker/postgres/initdb/` の初期化スクリプトで以下を行う。パスワードは環境変数から受け取り、スクリプトに書かない。

1. `secureflow_owner`・`secureflow_app` ロールを作成
2. データベース `secureflow` を owner 所有で作成（テスト用 `secureflow_test` も同様）
3. `REVOKE ALL ON DATABASE ... FROM PUBLIC`、`GRANT CONNECT ... TO secureflow_app`
4. `public` スキーマ：所有者を owner に変更、`REVOKE ALL ON SCHEMA public FROM PUBLIC`（`CREATE` だけでなく `USAGE` も PUBLIC から外す）、`GRANT USAGE ON SCHEMA public TO secureflow_app`
5. テスト用DBの所有者を `secureflow_test_owner` に変更する（`02-test-owner.sh`）。開発用の owner からテスト用DBへの接続権限、テスト用の owner から開発用DBへの接続権限は与えない
6. `secureflow_test_app` を作成し、テスト用DBへの接続とスキーマの USAGE のみを与える。`secureflow_app` のテスト用DBでの権限をすべて外す（`03-test-app.sh`）

**既存ボリュームへの追加：** 初期化スクリプトは初回起動時にしか動かないため、`scripts/add-test-roles.sh` で同じスクリプトを実行中のコンテナに流す（冪等）。ボリュームは破棄しない。`REASSIGN OWNED` は開発用DBの所有者まで変更するため使わない。

**既定権限（DEFAULT PRIVILEGES）は付与しない。** 各マイグレーションで、テーブルごとに必要な権限だけを明示的に `GRANT` する（付与漏れは app からのアクセス失敗＝fail closed になり、テストで検出される）。`migrations` テーブルへの権限は app に与えない。

### 4.2 テーブル権限

| テーブル | secureflow_app の権限 |
|---|---|
| organizations, organization_settings, users, security_test_runs | SELECT, INSERT, UPDATE |
| security_findings | SELECT, INSERT。UPDATE は `status`, `status_note`, `status_changed_by`, `status_changed_at`, `updated_at` のみ |
| ai_analysis_requests | SELECT, INSERT。UPDATE は `status`, `input_masked`, `input_scan_id`, `output_scan_id`, `workflow_id`, `error_code`, `started_at`, `heartbeat_at`, `finished_at`, `updated_at` のみ |
| workflows | SELECT, INSERT。UPDATE は `title`, `status`, `current_revision_id`, `max_severity`, `lock_version`, `submitted_at`, `updated_at` のみ |
| workflow_tasks | SELECT, INSERT, DELETE。UPDATE は `position`, `title`, `description`, `action_type`, `steps`, `priority`, `target_data`, `impact_summary`, `derived_permissions`, `ai_claimed_permissions`, `policy_decision`, `updated_at` のみ |
| workflow_executions | SELECT, INSERT。UPDATE は `status`, `started_at`, `heartbeat_at`, `finished_at`, `result`, `error_code`, `updated_at` のみ |
| **approvals, workflow_revisions, security_scans, ai_usage_logs, security_test_results** | **SELECT, INSERT のみ** |
| **audit_logs** | **SELECT のみ**（追記は `audit_append()` の EXECUTE を通じてのみ行う） |
| **audit_chain_heads** | **SELECT のみ** |
| jobs | SELECT, INSERT, UPDATE, DELETE（シーケンスの USAGE を含む。工程1-6） |
| failed_jobs | SELECT, INSERT, DELETE（シーケンスの USAGE を含む。工程1-6） |

| 関数 | secureflow_app の権限 |
|---|---|
| `audit_append()` | EXECUTE（§3.12.4）。その他の監査用の関数には権限なし |

**`audit_logs` の追記権限（工程1-3で変更）：** 工程1-1では `id` を除く列への INSERT を app ロールに与えていたが、app が `chain_seq`・`prev_hash`・`hash` を自由に指定できる状態ではチェーンの一貫性を保証できないため、工程1-3で **INSERT 権限を REVOKE する。** app ロールは `audit_logs` に直接 INSERT できず、`audit_chain_heads` を直接 INSERT・UPDATE・DELETE できない。IDENTITY 列のシーケンスにも権限を付与しない。

### 4.3 マイグレーションの実行経路

- マイグレーションは**専用の `migrate` サービス**（Compose の `tools` プロファイル）でのみ実行する：`docker compose run --rm migrate`（内部で `php artisan migrate --database=pgsql_migrator --force`）。
- `pgsql_migrator` 接続の認証情報は、`migrate` サービスには `secureflow_owner`、`test` サービスには `secureflow_test_owner` を渡す。`test` サービスに開発用の owner の認証情報は渡さない。`app` コンテナで `php artisan migrate` を実行しても app ロールに DDL 権限がないため失敗する。
- `test` サービスは owner 接続を **テスト用DBのスキーマ初期化とマイグレーションにのみ** 使う。テスト本体のクエリは `secureflow_test_app` の接続で行い、権限不足を見逃さない（[test-strategy.md](test-strategy.md)）。`test` サービスには `secureflow_app` の認証情報も渡さない。
- テスト用の2ロールは開発用DBに接続できず、開発用の2ロールはテスト用DBに接続できない。この分離はDB権限で担保される。
- マイグレーションは接続設定の app ロール（開発用DBでは `secureflow_app`、テスト用DBでは `secureflow_test_app`）に権限を付与する。

### 4.4 Phase 0 時点のスキーマ

Phase 0 では業務テーブルを作成しない（Laravel 雛形の既定マイグレーションは Phase 1 の設計に合わないため削除する）。マイグレーション経路とロール分離の検証のみを行う。

### 4.5 破壊的なDB操作

| コマンド | テスト用DB（§4.6 のガード通過時） | 開発用DB | 本番相当 |
|---|---|---|---|
| `migrate` | 可 | 可（`migrate` サービス） | 可（`migrate` サービス） |
| `migrate:rollback` | 可 | **管理された手順でのみ可** | 不可 |
| `migrate:fresh`、`migrate:refresh`、`migrate:reset`、`db:wipe` | 可 | 不可 | 不可 |
| `key:generate`、`queue:clear`、`queue:flush` | 可 | 可 | 不可 |
| `db:seed`、`schema:dump` | 可 | **管理された手順でのみ可** | 不可 |
| `cache:clear` | 可 | 可 | 可 |

「本番相当」は `APP_ENV` が `local`・`testing` のいずれでもない環境（未知の値を含む）とする。

Laravel 13.39.0 の `DB::prohibitDestructiveCommands()` は `migrate:fresh`・`migrate:refresh`・`migrate:reset`・`db:wipe` に加えて `migrate:rollback` も禁止するため使用しない（実機で確認済み）。各コマンドクラスの `prohibit()` で個別に制御する。

**`db:seed`・`schema:dump` の手順：** 実行前に `.env` の `COMPOSE_PROJECT_NAME` で対象を確認する。`db:seed` は `--class` で Seeder を指定する。`schema:dump` は `migrate` サービスで実行し、マイグレーションファイルを削除する `--prune` は使わない。

**開発用DBの rollback の手順：**

1. 対象を確認する：`.env` の `COMPOSE_PROJECT_NAME` と `docker compose run --rm migrate php artisan migrate:status --database=pgsql_migrator`
2. 開発用DBをリポジトリの外にバックアップする（パスワードハッシュを含むため、コミットしない）
3. `migrate` サービスで、段数を明示して実行する：`docker compose run --rm migrate php artisan migrate:rollback --database=pgsql_migrator --step=<段数>`
4. `migrate:status` と `verify-infra.sh` で結果を確認する

`audit_logs` を対象にする rollback は監査ログを失うため、開発用DBで必要な場合に限る。app ロールには DDL 権限がないため、`app` / `worker` / `scheduler` からは実行できない。

**工程1-3のマイグレーションの条件：** 既存のマイグレーションは変更せず、新しいマイグレーションを追加する。チェーンの列は既存の行から復元できないため、**`audit_logs` に行がある場合、`up` は例外で中断する。** `down` も、行がある場合はチェーンの列を失うため中断する。シーケンスは変更しない。

**工程1-3の開発用DBへの適用手順（適用は別途承認）：**

1. 工程1-1適用後・Seeder 実行後の状態のバックアップを取得する。バックアップのチェックサムを記録し、リポジトリの外に保管する（パスワードハッシュを含みうるため、コミットしない）
2. そのバックアップを使い捨てのDBへ復元し、マイグレーションと検証をそこで先に実行する
3. `audit_logs` が0行で、`audit_logs_id_seq` が記録どおり（§3.12）であることを読み取りのみで確認する
4. `migrate` サービスで適用し、`migrate:status`・権限・関数の属性を確認する

**バックアップの保護：** 開発用DBのバックアップには、パスワードハッシュと、期限内の `users.password_change_previous_hash` が含まれうる。どちらも秘密として扱い、リポジトリの外に置き、コミットせず、ファイルの権限を所有者のみとする。公開環境では暗号化し、保持期間を過ぎたものは削除する。

**復元の手順：** 所有者とロールを作成済みの空のDBに対して、`pg_restore -U postgres --exit-on-error --role=secureflow_owner -d secureflow <dump>` を実行する。スーパーユーザーのまま `--create` で復元すると、`citext` 拡張の所有者が `postgres` になり、以後の所有者ロールでの rollback が失敗する。バックアップから復元すると、チェーンはその時点まで巻き戻るため、復元後の `audit:head` の出力は新しい基準として保管する（以前に保管した新しい時点のヘッドとは `ANCHOR_MISMATCH` になる）。

### 4.6 テスト用DBのガード

スキーマのリセットの前に必ずガードを実行し、**すべて満たさない場合は例外で中断する**。解除用のフラグや環境変数は設けない。

| 区分 | 条件 |
|---|---|
| 環境 | `APP_ENV` が完全一致で `testing` |
| 設定 | 両接続のDB名が完全一致で `secureflow_test`（接頭辞・接尾辞で判定しない）、`DB_URL` が空、ホストとポートが想定どおり（`postgres:5432`） |
| 実接続 | `current_database()` が `secureflow_test`、接続ユーザーが想定ロール（`secureflow_test_owner` / `secureflow_test_app`）、スーパーユーザーでない、NOCREATEDB、どちらも開発用DBへの接続権限を持たない |

- コマンドの禁止（§4.5）の解除も、`APP_ENV` だけでは行わず、設定の条件をすべて満たす場合に限る。これにより、`APP_ENV=testing` を指定しても開発用DBには実行できない。
- コマンドラインから実行された場合も、`CommandStarting` イベントで実接続の条件を確認し、`--database` がテスト用 owner の接続以外なら中断する。Laravel は `APP_ENV=testing` ではこのイベントを既定で発火しないため、明示的に有効にする。
- **DB自体の作成・削除は PostgreSQL の初期化スクリプトに限定する。** owner は NOCREATEDB のため、テストやアプリからは実行できない。テストが行うのは、テスト用DB内のスキーマのリセットのみ。
- テスト本体は `secureflow_test_app` ロールで実行する。owner 接続はスキーマの初期化とマイグレーションに限定する。
- `db:wipe` は関数と拡張を削除しないことを確認済みのため、マイグレーションでは `CREATE OR REPLACE FUNCTION` と `CREATE EXTENSION IF NOT EXISTS` を使う。

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

`audit_append()` は所有者の権限で INSERT するが、このトリガーは INSERT を対象にしないため影響しない。

**残存リスク：** スキーマ所有者・スーパーユーザーはトリガーを無効化できる。ハッシュチェーンで改ざんの「検出」は可能だが、チェーン全体の再計算と、末尾の削除とヘッドの巻き戻しの組み合わせは、DB の中の情報だけでは検出できない（§3.12.5）。MVP では `audit:head` の出力を手動でDBの外へ保管することで、保管時点までの範囲を検出できる。自動退避は将来の拡張候補「チェーン先頭ハッシュの外部ストレージ（例：S3 Object Lock）への定期退避」で対処する（[development-roadmap.md](development-roadmap.md)）。

## 6. データ分類と保持

| 分類 | 該当 | 扱い |
|---|---|---|
| 秘密 | パスワード（ハッシュのみ）、APIキー（DBに保存しない） | — |
| マスク済みユーザー内容 | source_input_masked、workflow_tasks本文、plan_snapshot、masked_excerpt、ai_analysis_requests.input_masked | 原文は保存しない。input_masked は完了時NULL化 |
| 運用メタデータ | audit_logs、ai_usage_logs、security_scans | 本文を含めない |

保持期間（方針。MVPでは自動削除は実装しない）：監査ログ1年、スキャン・利用ログ90日。削除手順は追記専用制約と両立する専用メンテナンス手順として将来設計する。

認証・秘密情報（APIキー・トークン・パスワード・秘密鍵）を含む入力は処理を停止するため、マスク済みの形でも業務テーブルには保存されない（`security_findings` にはルールIDと位置のみ記録）。

**注意：** マスキングは検出できた情報にしか適用されない。氏名・住所など MVP で十分に検出できない情報が、マスク済みテキストに残っている可能性がある（[security-design.md §4](security-design.md)）。
