# SecureFlow AI — アーキテクチャ設計書

- 版：v1.7（2026-11-06）
- 状態：確定（v1.7：工程1-6 のキューの方式、時間制限、停滞回収を反映。v1.6：環境変数を Compose からコンテナへ渡す条件を明記。v1.5：工程1-4 の AI の起動条件と再試行を反映。v1.4：工程1-3 の監査ログの判断を反映。v1.3：環境変数と工程1-2 の判断を反映。v1.2：owner 認証情報の範囲と healthcheck を反映。v1.1：Q-D13・Q-PII・D11・Phase 0 追加条件を反映）
- 関連：[database-design.md](database-design.md) / [api-design.md](api-design.md) / [security-design.md](security-design.md) / [threat-model.md](threat-model.md) / [test-strategy.md](test-strategy.md) / [development-roadmap.md](development-roadmap.md)

---

## 1. 基本原則

1. **AIは「提案を返す関数」であり、行動主体ではない。** AIにはツール呼び出し・コード実行・DBアクセス・外部通信の能力を一切与えない。
2. **AIへの入力・AIからの出力はすべて未信頼データ。** 入力は検査・マスキング後に送信し、出力はスキーマ検証・許可リスト照合・無害化を経てから保存する。
3. **検出は失敗しうる前提で多層防御とする。** プロンプトインジェクション検出ルールは完全な防御手段ではない。最終防御層は「AIに実行権限を与えないこと」と「サーバー側許可リストに存在する操作しか実行できない実行器」である。
4. **重要な操作は人間の承認を経る。** 承認は処理内容のハッシュに紐付け、内容が変われば無効になる。
5. **原文・秘密情報を残さない。** 永続化するのはマスキング後の文章のみ。認証・秘密情報（APIキー、トークン、パスワード、秘密鍵）を含む入力は原則として処理を停止する。マスキングに失敗した場合は fail closed（停止）とする。
6. **重大度（severity）と処理動作（action）を分離する。** 検出結果の重さと、システムがとる動作（記録・警告・マスキングして続行・停止）は別々に定義する（[security-design.md §3](security-design.md)）。
7. **すべてのAPIで認証・組織・ユーザー・ロールの認可を行う。** UUIDは推測困難性を高める補助であり、認可の代替ではない。
8. **申請者と承認者は必ず別ユーザー。** 承認できるのは admin のみで、自分が作成したワークフローは承認できない。承認可能な admin がいなければ実行できない。

## 2. 防御層

| 層 | 内容 | この層が破られても… |
|---|---|---|
| L1 入力検査 | 個人情報のマスキング、認証・秘密情報の検出による停止、プロンプトインジェクション検出（ルールベース）、マスキング失敗時の fail closed | 検出漏れは前提。L2以降で無害化 |
| L2 AI能力の剥奪 | Function Calling / tools を使用しない。AIはJSONを返すのみ | インジェクションが成功してもAIは何も実行できない（**最終防御層の一つ**） |
| L3 出力検証 | JSONスキーマ検証、操作種別の許可リスト照合、出力側機密情報検査、カナリア検知、HTML除去 | 不正操作は `forbidden` として提出不可 |
| L4 人間の承認 | 正規化した実行計画のSHA-256ハッシュに承認を紐付け。自己承認禁止 | 承認後の変更は自動で承認無効 |
| L5 実行時再検証・実行器 | 実行直前の再検証。禁止操作の実行ハンドラはコード上に存在しない | 上位層にバグがあっても禁止操作は実行不能（**最終防御層**） |

## 3. システム構成

```
┌──────────── Browser（未信頼） ─────────────┐
│ React + TypeScript + Vite + Tailwind CSS    │
│ ・AI出力はReactのテキスト描画のみ            │
│ ・dangerouslySetInnerHTML / Markdown描画禁止 │
└───────────────┬─────────────────────────────┘
                │ 同一オリジン / Cookieセッション + CSRFトークン
┌───────────────▼─────────────────────────────┐
│ nginx：静的配信・/api と /sanctum をproxy     │
│        セキュリティヘッダ・CSP付与            │
└───────────────┬─────────────────────────────┘
┌───────────────▼──────────── Laravel API（信頼境界内） ─────────────────┐
│ Http      : Controller(薄い) / FormRequest / Policy / Middleware        │
│ Domain    : WorkflowService, WorkflowStateMachine, PlanHasher,          │
│             ApprovalService, ExecutionService, ExecutionVerifier,        │
│             Simulators（許可された操作種別ごとのハンドラのみ）           │
│ Security  : InputScanner[Normalizer, PiiDetector, SecretDetector,       │
│             InjectionDetector, RiskAggregator], Masker,                 │
│             OutputValidator, ActionCatalog（許可リスト・ポリシー版）     │
│ Ai        : AiGateway（上限・タイムアウト・利用記録）→ AiProvider        │
│               ├ MockAiProvider（開発・テスト・CI・自己診断）            │
│               └ OpenAiProvider（Phase 2〜、Structured Outputs、tools無し）│
│ Audit     : AuditLogger → audit_append()（DB関数）、AuditChainVerifier  │
│ SelfTest  : SecuritySelfTestRunner                                      │
└──────┬─────────────────────┬────────────────────────┬──────────────────┘
       │                     │                        │ 送信先は環境変数で固定（SSRF対策）
┌──────▼──────┐   ┌──────────▼───────────┐   ┌────────▼─────────┐
│ PostgreSQL  │   │ Redis                │   │ OpenAI API       │
│ 2ロール分離 │   │ キュー/セッション/    │   │ 出力は未信頼     │
│ (owner/app) │   │ レート制限/キャッシュ │   └──────────────────┘
└──────▲──────┘   └──────────▲───────────┘
       └──────────┬──────────┘
          ┌───────┴────────┐
          │ Queue Worker   │ AnalyzeWorkflowJob / ExecuteWorkflowJob /
          │ + Scheduler    │ RunSecuritySelfTestJob / 停滞ジョブ回収
          └────────────────┘
```

## 4. コンテナ構成（Docker Compose）

| サービス | 役割 | 公開ポート | DB接続ロール |
|---|---|---|---|
| `nginx` | フロントエンド配信、APIリバースプロキシ、ヘッダ付与 | `127.0.0.1:8080` | — |
| `app` | php-fpm（Laravel） | なし | `secureflow_app` |
| `worker` | `queue:work`（appと同一イメージ） | なし | `secureflow_app` |
| `scheduler` | `schedule:work`（停滞実行の回収等） | なし | `secureflow_app` |
| `migrate` | マイグレーション専用（`tools` プロファイル。`docker compose run --rm migrate` で実行し終了） | なし | `secureflow_owner` |
| `postgres` | PostgreSQL。初期化スクリプトで owner / app ロールを作成 | **なし（ホストに公開しない）** | — |
| `redis` | `requirepass` 必須 | **なし（ホストに公開しない）** | — |
| `frontend` | 開発時のVite dev server（本番相当ではビルド成果物をnginxが配信） | `127.0.0.1:5173` | — |

- 公開するポートは `127.0.0.1` にバインドし、LANへ公開しない。DB・Redis はホストに公開せず、Compose 内部ネットワークからのみ到達できる（調査が必要な場合は `docker compose exec postgres psql` を使う）。
- **owner ロールの認証情報は `migrate` サービスにのみ渡す。** `test` サービスには、開発用DBに接続できないテスト専用のロール（`secureflow_test_owner`・`secureflow_test_app`）のみを渡す（[database-design.md §4.3・§4.6](database-design.md)）。`app` / `worker` / `scheduler` のコンテナには owner のパスワードが存在しないため、通常のLaravel実行経路からDDLは実行できない（`php artisan migrate` を app コンテナで実行しても権限不足で失敗する＝fail closed）。
- コンテナイメージは実際に採用したバージョンのタグで固定し、README に記載する。
- **`worker` の定期的な再起動は想定された動作である。** `queue:work --max-time=3600` で約1時間ごとに終了し、`restart: unless-stopped` で再起動する。起動時間が他のサービスより短いことを、異常な再起動と混同しない。

### 4.1 開発環境

- 開発場所は **WSL2 の Linux ファイルシステム内**（`~/projects/secureflow-ai`）。Windows ドライブ（`/mnt/c`）上には置かない（bind mount の性能とファイル権限のため）。
- Docker Desktop の WSL2 連携を使用する。
- PHP・Composer は**ホストにインストールせず、Docker コンテナ内でのみ実行**する。Node.js もコンテナ内での実行を基本とする。

### 4.2 ヘルスチェック

| エンドポイント | 種別 | 判定 | 応答 |
|---|---|---|---|
| `GET /api/health/live` | Liveness | PHPプロセスが応答できるか（外部依存を確認しない） | 200 `{"status":"ok"}` |
| `GET /api/health/ready` | Readiness | DB（appロールで `SELECT 1`）と Redis（`PING`）に到達できるか | 200 `{"status":"ok"}` ／ 503 `{"status":"unavailable"}` |

応答にはバージョン・ホスト名・接続先・接続文字列・エラー詳細・例外メッセージを含めない。通常の API エラーは RFC 9457 形式だが、ヘルスチェックはこの形式を維持し、監視側は HTTP ステータスコードと `status` で判定する。**liveness と readiness を混同しない：** readiness はトラフィックの制御のみ、liveness は再起動の判断のみに使い、readiness の 503 を理由にコンテナを自動で再起動しない。readiness は DB と Redis の到達性に加えて、ストレージの障害の疑い（`storage_scope=db_suspected`）でも 503 とする（[security-design.md §16.5.1](security-design.md)）。失敗の詳細はアプリケーションログにのみ記録する。Docker の healthcheck は nginx・app・worker・scheduler が liveness（DB・Redis に接続しない）、起動順序の制御には postgres・redis 自身の healthcheck を使う。app はソースの存在、php-fpm の応答、Laravel の起動を確認する。worker・scheduler はソースの存在、Laravel の起動、`queue:work` / `schedule:work` の実プロセスを確認し、処理するジョブがないだけでは unhealthy にしない。

## 5. ディレクトリ構成

```
/
├─ backend/                     Laravel
│  ├─ app/
│  │  ├─ Http/Controllers/Api/V1/   Requests/   Resources/   Middleware/
│  │  ├─ Policies/
│  │  ├─ Models/
│  │  ├─ Domain/
│  │  │  ├─ Workflow/   (WorkflowService, WorkflowStateMachine, PlanHasher, RevisionService)
│  │  │  ├─ Approval/   (ApprovalService)
│  │  │  └─ Execution/  (ExecutionService, ExecutionVerifier, Simulators/*)
│  │  ├─ Security/
│  │  │  ├─ Scanning/   (InputScanner, Normalizer, Detectors/*, Masker, RiskAggregator)
│  │  │  ├─ Output/     (OutputValidator, AiTaskSchema)
│  │  │  └─ Policy/     (ActionCatalog, PermissionPolicy)
│  │  ├─ Ai/            (Contracts/AiProvider, Providers/*, AiGateway, PromptBuilder, UsageLimiter)
│  │  ├─ Audit/         (AuditLogger, AuditEventType, AuditCanonicalizer, AuditChainVerifier)
│  │  ├─ SelfTest/      (SecuritySelfTestRunner, Cases/*)
│  │  ├─ Jobs/
│  │  └─ Console/Commands/ (user:create, executions:reap-stale, audit:verify, audit:head, audit:status)
│  ├─ database/migrations/  seeders/
│  ├─ resources/security/   (injection-rules, 攻撃コーパス)
│  └─ tests/ Unit/ Feature/ Security/ Isolation/
├─ frontend/
│  └─ src/ api/ components/ features/{auth,dashboard,workflows,approvals,security,audit,settings}/ routes/ lib/
├─ docker/  nginx/ php/ postgres/initdb/
├─ e2e/     Playwright
├─ docs/
└─ .github/workflows/
```

方針：MVCを基本とし、ビジネスロジックは `Domain`、セキュリティ検査は `Security` に独立させる。過度な抽象化は避け、インタフェースを置くのは差し替えが要件になっている箇所（`AiProvider`、検出器）に限定する。

## 6. フロントエンド構成

- ルーティング：React Router。認証ガード付きルートとロール別表示制御（表示制御はUXのためであり、認可はサーバー側で必ず実施）。
- データ取得：TanStack Query。APIレスポンスは zod で型検証してから使用する。
- 状態：サーバー状態はTanStack Query、UI状態はReactローカル状態。グローバルストアは導入しない。
- グラフ：Recharts。
- 描画規則：AI出力・ユーザー入力由来の文字列は必ず `{text}` のテキスト描画。`dangerouslySetInnerHTML` はESLintでエラー化。URLの自動リンク化もしない。
- トークン類を `localStorage` / `sessionStorage` に保存しない（Cookieセッションのみ）。

## 7. AI処理パイプライン

```
User ─POST /analyses─▶ API
  1. 入力長検証（既定4,000文字）・利用上限の事前確認
  2. InputScanner
     a. Normalizer：NFKC、ゼロ幅文字除去、空白正規化（検出用コピーに適用）
     b. Secret/PII 検出 → 各検出に severity と action を付与
        ・個人情報（メール・電話・カード・マイナンバー等）：action = mask_continue
        ・認証・秘密情報（APIキー・トークン・パスワード・秘密鍵）：action = block
     c. Masker で置換（マスク済みテキスト生成）→ マスク済みテキストを再検査し、
        検出が残る／マスキング処理が例外になった場合は fail closed（action = block）
     d. InjectionDetector：正規化テキストに対しルール検出・スコアリング
        （High/Critical：block、Medium：warn、Low：record）
     e. RiskAggregator：最大 severity と、全検出の action から全体判定（allow / warn / block）を算出
        （block が1つでもあれば block）
     ※ 原文はこのリクエスト処理中のメモリ上にのみ存在し、永続化・ログ出力しない
  3. 判定 block → AIを呼ばず、scan/findings と監査ログのみ記録して 422 `INPUT_BLOCKED` で返す
     warn → 続行（以降の画面で警告表示・承認時に確認必須）／ allow → 続行（検出は記録）
  4. ai_analysis_requests にマスク済みテキストを保存し、AnalyzeWorkflowJob を投入（202）
     ※ 工程2-3 までは検査もマスキングもなく、入力を保存しない（文字数のみ記録）。モック AI は入力を使わない
Worker
  5. PromptBuilder：固定システムプロンプト（秘密情報なし・カナリア含む）＋
     ランダム境界文字列で囲んだマスク済み入力（「データとして扱え」と明示）
  6. AiGateway：予算確認 → Provider呼び出し（tools無し、JSON Schema指定、
     max_output_tokens上限、タイムアウト30秒、5xx/429/タイムアウトのみ指数バックオフで最大2回）
     → ai_usage_logs 記録（本文は記録しない）
     ※ 予算確認と ai_usage_logs は工程2-8。工程1-4 の AiGateway は呼び出しと再試行のみ
  7. OutputValidator：JSON解析 → スキーマ検証（未知キー拒否・長さ上限・列挙値）
     → action_type を ActionCatalog と照合 → 出力の個人情報は再マスキング、
     認証・秘密情報が出力に含まれる場合は分析を blocked（fail closed）
     → カナリア検知 → HTMLタグ除去 → プレーンテキスト化
  8. PermissionPolicy：権限は ActionCatalog から導出。AI申告の権限とは照合のみ（不一致は finding）
  9. Workflow(Draft) + Revision#1 + Tasks を保存、ai_analysis_requests の入力本文を NULL 化
 10. 監査ログ記録
User ─GET /analyses/{id}─▶ 状態ポーリング → workflow_id 取得
```

## 8. 操作カタログ（サーバー側許可リスト）

`ActionCatalog` はコード上の定数として定義し、`policy_version`（例 `2026.11.1`）を持つ。変更時はバージョンを上げる。

| action_type | MVP判定 | 導出権限 | 模擬実行ハンドラ |
|---|---|---|---|
| `text.analyze` | allowed | `ai.text.read` | あり |
| `text.summarize` | allowed | `ai.text.read` | あり |
| `report.draft` | allowed | `ai.text.read`, `report.draft.write` | あり（下書き生成のみ） |
| `task.create` | allowed（サーバー制御） | `task.write` | あり |
| `email.send` | forbidden | `external.email.send` | **存在しない** |
| `file.delete` | forbidden | `file.delete` | **存在しない** |
| `shell.exec` | forbidden | `system.shell` | **存在しない** |
| `db.query` | forbidden | `system.database` | **存在しない** |
| `http.request` | forbidden | `external.http` | **存在しない** |
| 上記以外 | スキーマ違反として拒否 | — | — |

`forbidden` を含むワークフローは提出（Pending化）できない。ユーザー編集でも同じ判定を通る。

## 9. ワークフロー状態遷移

```
Draft ──submit──▶ Pending ──approve──▶ Approved ──execute──▶ Running ──▶ Completed
  ▲                 │  │                  │                     └──────▶ Failed
  │                 │  └──reject──▶ Rejected                              │
  │                 │                  │                                   │
  └──edit（新Revision作成）◀───────────┴── reopen（新Revision作成）◀───────┘
     ※ Pending / Approved 中の edit も Draft に戻る（承認は計算上無効化）
     ※ Running / Completed は編集不可
```

| 遷移 | 実行者 | 条件 |
|---|---|---|
| Draft→Pending（submit） | 作成者 | forbidden操作なし、最新Revisionの検査判定が block でない |
| Pending→Approved（approve） | admin（**作成者本人を除く**。auditor・member は不可） | revision・plan_hash一致、Medium以上はリスク確認チェック必須 |
| Pending→Rejected（reject） | admin（**作成者本人を除く**） | 理由必須 |
| Pending/Approved/Draft→Draft（edit） | 作成者 | 新Revision作成、再検査 |
| Rejected/Failed→Draft（reopen） | 作成者 | 新Revision作成（内容同一でもrevision_noが変わるためハッシュも変わる） |
| Approved→Running（execute） | 作成者 または admin | 実行時再検証すべて合格 |
| Running→Completed/Failed | システム | 実行結果 / 障害・停滞回収 |

**承認者不在時の扱い：** 組織内に「作成者以外の有効な admin」が存在しない場合、そのワークフローは承認されず Pending のまま留まり、実行できない（承認を経ない実行経路は存在しない）。提出時と承認待ち一覧ではこの状態を「承認可能な管理者がいません」と表示する。提出自体は拒否しない（後から admin が追加されれば承認できるため）。

## 10. 非同期処理

| ジョブ | キュー | 再試行 | 一意性 | 障害時 |
|---|---|---|---|---|
| AnalyzeWorkflowJob | `ai` | AI呼び出しはGateway内で最大2回。ジョブ自体は1回 | `queued → processing` の条件付き UPDATE（DB で判定。`ShouldBeUnique` は使わない） | `failed` に遷移、監査ログ `analysis.failed` |
| ExecuteWorkflowJob | `execution` | **自動再試行しない**（承認は1回限り消費） | `ShouldBeUnique`（execution_id）＋DB一意制約 | Failed、reopen→再承認が必要 |
| RunSecuritySelfTestJob | `selftest` | なし | 同時に1件のみ | run を failed |
| 停滞回収（scheduler、毎分） | — | — | — | heartbeatがタイムアウトした Running 実行・processing 分析を Failed 化し監査ログ |

ジョブには ID のみを渡す（本文をキューに載せない）。

**キューの方式（工程1-6で決定）：DB キューとする。** `QUEUE_CONNECTION=database`、`queue:work database --queue=ai --tries=1`。

| 方式 | 消失 | 古いデータからの復活 | 投入とコミットの整合 |
|---|---|---|---|
| Redis AOF | `everysec` で最大1秒分 | 減るが残る | ずれが残る |
| **DB キュー（採用）** | なし | なし | 業務データと同じトランザクション |
| Outbox + Redis | なし | 残る | 整合するが中継処理が必要 |

- **投入はトランザクションの中で行う（`after_commit=false`）。** 行とジョブは一緒にコミットされ、一緒にロールバックされる。
- 全ての API は既に DB に依存しているため、新しい障害点を増やさない。
- **業務の状態は DB の行を正とする。** `failed_jobs` の記録だけで業務の失敗と判断しない。
- 二重に取り出されても、条件付き UPDATE により処理は1回のみ行われる。AI 呼び出しの間はトランザクションを開かない。

**時間制限（工程1-6で決定）：** AI 呼び出しの最長（`AiGateway::worstCaseSeconds()`、既定値で93秒）< ジョブと worker の `--timeout`（120秒）< `retry_after`（180秒）。`retry_after` は関係を崩さないよう環境変数にしない。`scripts/test-compose-env.sh` が CI で関係を確認する。

**停滞回収（工程1-6で実装）：** `analysis:recover` を毎分実行する。`processing` のまま180秒を超えた行と `queued` のまま15分を超えた行を `ANALYSIS_STALE` で `failed` にする。組織をまたいで読むのはこのコマンドのみで、各行の処理はその組織の文脈の中で行う。回収の後に元の処理が戻っても、行のロックの下で状態を確認するため何も保存しない。

**以下は工程1-3 で Redis キューについて確認した記録である。工程1-6 で DB キューへ移行したため、業務のジョブには適用されない。** 検証は `scripts/test-worker-failure.sh`（AUDIT-WORKER-01）に置き換えた。

**既知の制約：Redis キューのジョブの消失と二重実行（2026-11-05 に再現済み。隔離した環境、当時の `scripts/test-worker-redis-failure.sh`、テスト用のジョブ）：** 次の現象は未検証の懸念ではなく、**再現を確認した既知の制約である。** 工程1-3の時点で業務のジョブと `failed_jobs` テーブルはない（工程1-6で導入する）。`queue:work --tries=1`、`retry_after=90`、Redis は `appendonly no`。

| 状況 | ジョブ | 副作用 | 記録 |
|---|---|---|---|
| Redis の停止中に投入 | 投入元に `RedisException` が届く | なし | — |
| 待機中に Redis を通常停止 | **残る**（停止時の RDB） | 1回 | — |
| 待機中に Redis を**強制終了** | **失われる。投入元には伝わらない** | 0回 | なし |
| 同上の再起動で古い RDB を読む | **処理済みのジョブが復活する** | **2回**（3回の実行で毎回再現。`attempt=1` のまま） | なし |
| 実行中に Redis を通常停止し、`worker` の再試行の間に復旧 | 完了の処理が復旧後に届いて消える | 1回 | なし |
| 実行中に長時間停止 | 予約に残る。`retry_after` の後に取り出され、`--tries=1` のため**再実行せず失敗にする** | 1回 | **`failed_jobs` がなければ `42P01` で記録されず消える。** あれば `MaxAttemptsExceededException` で1行（**完了したジョブが失敗として残る**） |
| 実行中に Redis を強制終了 | 消える | 1回 | なし |

`worker` は Redis の停止中に異常終了と再起動を繰り返し（1回の長時間の停止で5回）、復旧後は追加の操作なしに新しいジョブを処理する。

**工程1-6 が完了するまでの規則：**

- **Redis キューに業務上重要なジョブを投入しない。消失すると困る業務ジョブを、工程1-6 の完了前に Redis キューで実行しない。**
- **Redis の `ShouldBeUnique` だけでは二重実行を防止できない。** ロックも同じ Redis にあり、キューと一緒に消失または復活する。
- **実ジョブの導入の前に、DB 側の一意制約や状態の条件付き更新などによる冪等性を実装する。** 副作用の前に DB で判定する。
- `compose.yaml` と `worker` のキューの方式は工程1-3では変更しない。

**工程1-6 への引き継ぎ：**

| 事項 | 内容 |
|---|---|
| 永続化の方式 | **Redis AOF、DB キュー、Outbox パターンなどを比較して決定する。** 投入の取りこぼし（強制終了で投入元に伝わらない消失）と、古いスナップショットからの復活の両方を判断の対象とする |
| 冪等性 | 上記のとおり DB で判定する。設計済みの `ShouldBeUnique` と DB の一意制約の組み合わせ（上の表の `ExecuteWorkflowJob`）を、再現した復活のケースで確認する |
| `failed_jobs` と業務の成否の区別 | **`failed_jobs` の記録と実際の業務処理の成否を区別する。** 再現のとおり、完了したジョブが `MaxAttemptsExceededException` で失敗として記録されるため、`failed_jobs` だけで業務の失敗と判断しない。業務の状態は DB を正とする。テーブルと権限は [database-design.md §3.15](database-design.md) |
| `timeout` と `retry_after` | **`timeout` と `retry_after` の関係を設計し、検証する。** 現在は `retry_after=90` でジョブの `timeout` は未設定であり、`retry_after` より長いジョブが並行して再度取り出される可能性がある（未検証） |

## 11. 設定管理（環境変数）

| 変数 | 用途 | 既定 |
|---|---|---|
| `APP_ENV` / `APP_DEBUG` / `APP_KEY` | Laravel標準 | `APP_DEBUG=false`（開発時のみtrue） |
| `DB_*` | 実行用ロール（`secureflow_app`）。app / worker / scheduler に渡す | — |
| `DB_MIGRATOR_*` | マイグレーション用ロール（`secureflow_owner`）。**`migrate` サービスにのみ渡す** | — |
| `DB_TEST_USERNAME` / `DB_TEST_PASSWORD` | テスト本体を実行するロール（`secureflow_test_app`）。**`test` サービスに `DB_USERNAME` / `DB_PASSWORD` として渡す**。`postgres` はロール作成にのみ使う | `secureflow_test_app` / 生成値 |
| `DB_TEST_MIGRATOR_USERNAME` / `DB_TEST_MIGRATOR_PASSWORD` | テスト用DBの owner（`secureflow_test_owner`）。**`test` サービスに `DB_MIGRATOR_*` として渡す**。`postgres` はロール作成にのみ使う | `secureflow_test_owner` / 生成値 |
| `COMPOSE_PROJECT_NAME` / `NGINX_PORT` / `FRONTEND_PORT` | 複数環境の分離 | `secureflow` / `8080` / `5173` |
| `REDIS_PASSWORD` | Redis認証 | 必須 |
| `AI_PROVIDER` | `mock` / `openai` | `mock` |
| `OPENAI_API_KEY` | APIキー（画面からは設定不可・表示不可） | 空 |
| `OPENAI_MODEL` | 使用モデル名（Phase 2実装前に確定） | 空 |
| `OPENAI_BASE_URL` | 送信先（固定値。画面から変更不可） | `https://api.openai.com/v1` |
| `AI_TIMEOUT_SECONDS` / `AI_MAX_OUTPUT_TOKENS` | 呼び出し制限 | 30 / 2000 |
| `SESSION_IDLE_MINUTES` / `SESSION_ABSOLUTE_HOURS` | セッション期限。`SESSION_IDLE_MINUTES` は `config/session.php` の `lifetime` に対応付ける（Laravel 標準の `SESSION_LIFETIME` は使わない）。`SESSION_ABSOLUTE_HOURS` は絶対期限のミドルウェアが参照する | 30 / 12 |
| `SANCTUM_STATEFUL_DOMAINS` | SPA認証を許可する `ホスト:ポート`（カンマ区切り、ワイルドカードなし）。開発環境では Compose が `localhost:${NGINX_PORT}`、`127.0.0.1:${NGINX_PORT}`、`localhost:${FRONTEND_PORT}`、`127.0.0.1:${FRONTEND_PORT}` を設定する | 上記 |
| `AUDIT_LOGIN_IP_LIMIT_PER_MINUTE` | `POST /auth/login` の IP 単位の制限（工程1-3。**実測に基づかない暫定値**。[security-design.md §16.5.4](security-design.md)） | 30 |
| `AUDIT_SYSTEM_CHAIN_LIMIT_PER_MINUTE` | システムチェーンへの匿名イベントの全体上限（工程1-3。**実測に基づかない暫定値**） | 600 |
| `DB_UNAVAILABLE_TTL_SECONDS` | DB unavailable の有効期間。経過後の要求から実際の DB 接続で再確認する（工程1-3。暫定値。[security-design.md §16.5.1](security-design.md)） | 30 |
| `AUDIT_RECHECK_INTERVAL_SECONDS` | Audit unavailable の回復を実際の追記で確認する間隔（工程1-3。暫定値） | 30 |
| `DB_CONNECT_TIMEOUT_SECONDS` | DB の接続のタイムアウト（`PDO::ATTR_TIMEOUT`。工程1-3。暫定値） | 2 |
| `DB_STATEMENT_TIMEOUT_MS` / `DB_LOCK_TIMEOUT_MS` / `DB_IDLE_IN_TX_TIMEOUT_MS` | app の接続の `server_options`（工程1-3。暫定値。`lock_timeout` は `statement_timeout` より短くする。[security-design.md §16.5.6](security-design.md)） | 5000 / 3000 / 30000 |
| `AUDIT_PREFLIGHT_TIMEOUT_MS` | 監査の事前確認の `statement_timeout`（工程1-3。暫定値） | 1000 |
| `DB_KEEPALIVES_IDLE` / `DB_KEEPALIVES_INTERVAL` / `DB_KEEPALIVES_COUNT` / `DB_TCP_USER_TIMEOUT_MS` | TCP のネットワーク断の検出（工程1-3。暫定値） | 5 / 2 / 3 / 5000 |
| `PASSWORD_CHANGE_REPLAY_MINUTES` | パスワード変更の `Idempotency-Key` で再試行を受け付ける期間（工程1-3。暫定値。[security-design.md §16.5.5](security-design.md)） | 15 |
| `AUDIT_PROBE_MIN_INTERVAL_SECONDS` | 確認プローブのコンテナ内の最小間隔（工程1-3。暫定値。[security-design.md §16.5.1](security-design.md)） | 5 |
| `PASSWORD_PENDING_REDIS_TIMEOUT_MS` / `PASSWORD_PENDING_REDIS_READ_TIMEOUT_MS` / `PASSWORD_PENDING_TTL_MARGIN_SECONDS` | パスワード変更の保留の指紋の書き込みの全体の期限（条件付きで確定。単調増加時計で判定し、超過は成功扱いにせずロールバックする）、読み取りのタイムアウト、キーの有効期限の余裕（工程1-3。[security-design.md §16.5.5](security-design.md)） | 1000 / 900 / 300 |
| `LOG_AGGREGATION_INTERVAL_SECONDS` | 障害中のログの集約の間隔（工程1-3。暫定値。[security-design.md §16.5.7](security-design.md)） | 60 |
| `REDIS_TIMEOUT` / `REDIS_READ_TIMEOUT` / `REDIS_MAX_RETRIES` | Redis の接続・読み取りのタイムアウトと再試行。障害中の待ち時間を決める（暫定値。AUDIT-LOAD-01 で確認） | 2 / 2 / 3 |

**Compose との関係：** コンテナに渡るのは `compose.yaml` に書かれた変数のみである。上の調整値を追加するときは `compose.yaml` にも同じ既定値で追加する（`scripts/test-compose-env.sh` が CI で確認する）。`.env` を変更した後はコンテナの再作成が必要である。

`AI_PROVIDER=openai` は、Phase 2 でマスキング・出力検証が完成し、必要なセキュリティテスト（[test-strategy.md §5](test-strategy.md) の ST-02〜04, 07, 10, 13〜19, 30, 31, 35〜37）を通過し、D11 の確認が完了するまで受け付けない（起動時の設定検証でエラー）。それまで OpenAiProvider はコード上も登録しない。

**起動時の設定検証（工程1-4）：** `mock` 以外の値（空、大文字を含む値を含む）と、`local`・`testing` 以外の環境の `mock` はエラーとする。したがって、工程2-8までは本番相当の環境では起動しない（公開環境は工程2-8以降の前提とする）。エラーにするのは AI に到達しうる入口、すなわち Web の起動と `queue:work`・`queue:listen`・`schedule:work`・`schedule:run` である。`migrate` などの管理コマンドは、障害時の対応を妨げないよう止めない。AI の呼び出し時（`AiProvider` の解決時）にも同じ検証を行うため、どの経路でも不正な設定のまま AI には到達しない。エラーのメッセージには設定値を含めない（秘密情報の誤設定に備える）。

## 12. 拡張性（Phase 4〜5）

- 外部連携は「操作カタログへの追加＋専用ハンドラ＋承認必須」の形でのみ追加する。汎用HTTPツールは追加しない。
- `AiProvider` インタフェースにより他プロバイダへ差し替え可能。
- AWS移行時：RDS（PostgreSQL）、ElastiCache（Redis）、ECS Fargate、Secrets Manager、CloudWatch。監査ログハッシュの外部退避先として S3 Object Lock を想定。

## 13. 技術選定

実際に採用したバージョンは Phase 0 で固定し、README の「採用バージョン」に記載する（本表は選定方針）。

| 分野 | 選定 | 理由 |
|---|---|---|
| バックエンド | Laravel（実装時点の最新安定版）/ PHP 8.4 | 要件指定。Queue・RateLimiter・Policy等が標準で揃う |
| 認証 | Laravel Sanctum（SPA Cookie認証） | トークンをブラウザストレージに置かずに済む。CSRF保護が標準 |
| テスト | Pest（PHPUnit上で動作） | 要件のPHPUnit/Pestを一本化 |
| 静的解析 | Larastan（PHPStan）レベル8、ESLint、Pint | 型安全性 |
| AI出力検証 | Laravel Validator + 未知キー拒否 | 追加依存を避ける |
| OpenAI通信 | Laravel HTTP Client | SDK依存を避け、タイムアウト・記録・送信先固定を自前制御 |
| フロントエンド | React / React Router / TanStack Query / zod / Recharts / Tailwind CSS v4 | 必要最小限 |
| E2E | Playwright | 要件指定 |
| セキュリティ検査 | Semgrep / Trivy / composer audit / npm audit | 要件指定＋標準ツール |

## 14. 設計判断記録

| ID | 決定 | 決定日 |
|---|---|---|
| D1 | ロールは admin / member / auditor。**自己承認は禁止** | 2026-11-03 |
| D2 | organizations テーブルを最初から作成 | 2026-11-03 |
| D3 | AI分析は非同期（キュー＋ポーリング） | 2026-11-03 |
| D4 | High / Critical は処理停止、Medium は警告付き続行、Low は記録のみ | 2026-11-03 |
| D5 | OpenAI APIキーは環境変数のみで管理 | 2026-11-03 |
| D6 | アプリ内セキュリティ自己診断を実装。CIテストはGitHub Actionsで別途実行 | 2026-11-03 |
| D7 | マスキング後の文章のみ保存。原文は保存しない | 2026-11-03 |
| D8 | ユーザーは管理コマンドで作成。Seeder はログイン可能な固定ユーザーを生成しない（D18）。公開サインアップなし | 2026-11-03（2026-11-04 更新） |
| D9 | Phase 1 はモックAIのみ | 2026-11-03 |
| D10 | Redis を導入 | 2026-11-03 |
| D11 | OpenAIモデル名は環境変数。Phase 2-8 の直前に、モデル・API仕様・データ保持・学習利用・送信データ範囲・レート制限等を確認する。マスキング・出力検証が完成し必要なセキュリティテストを通過するまで実接続を有効化しない | 2026-11-03 |
| D12 | 承認後の編集は Draft に戻し、再提出・再承認を必須とする | 2026-11-03 |
| D13（Q-D13） | 承認できるのは admin のみ。admin は他ユーザーが作成したワークフローのみ承認可能。auditor・member に承認権限なし。申請者と承認者は必ず別ユーザー。承認可能な admin がいなければ実行不可 | 2026-11-03 |
| D14（Q-PII） | 個人情報（メール・電話・カード・マイナンバー等）はマスキング後に続行可。認証・秘密情報（APIキー・トークン・パスワード・秘密鍵/PEM等）は原則停止。severity と action を分離。マスキング失敗時は fail closed。検出限界を画面・APIで明示し、検出漏れがないことを保証しない | 2026-11-03 |
| D15 | 開発場所は WSL2 の Linux ファイルシステム。PHP・Composer はコンテナ内のみ。DBロールは owner / app に分離しマイグレーションは専用経路。DB・Redis ポートは非公開。ヘルスチェックは Liveness / Readiness を分離 | 2026-11-03 |
| D16 | リポジトリは GitHub `TakahiroNago/secureflow-ai`（Public、MIT License） | 2026-11-03 |
| D17 | ログイン失敗は 401 `AUTH_FAILED` に統一。アカウントロック中も既存セッションと承認・実行は維持し（条件は `is_active = true` のみ）、`is_active=false` は既存セッションも即時無効化。パスワード変更では他のセッションを無効化し、現在のセッションは維持 | 2026-11-04 |
| D18 | ログインユーザーの作成は `user:create` に一本化する。初期データ投入は組織や初期設定などに限定し、ログイン可能な固定ユーザーを生成しない。公開リポジトリに既知の認証情報を残さないため | 2026-11-04 |
| D19 | 漏洩パスワード辞書は SecLists の個別ファイルから作成して同梱し、実行時に外部へ問い合わせない（出典・更新方針は [security-design.md §12.1](security-design.md)） | 2026-11-04 |
| D20 | 監査ログの追記は SECURITY DEFINER の DB 関数 `audit_append()` のみで行い、app ロールは監査テーブルに SELECT と関数の EXECUTE のみを持つ。チェーン順序は `chain_seq` で管理し、`audit_logs.id` を使わない。開発用DBの `audit_logs_id_seq` は現状（次の `id` は 6）を維持する（[database-design.md §3.12](database-design.md)） | 2026-11-04 |
| D21 | 組織に属さないイベントは NIL UUID のシステムチェーンに記録する。NIL UUID は組織 ID に使えず、システムチェーンは組織の利用者から参照できない。未知のメールアドレスは記録しない | 2026-11-04 |
| D22 | 検証は PHP の検証器と `audit:verify` で独立に行い、API は工程2-7 とする。検証に失敗してもサービスを自動停止せず、自動修復しない。`audit:head` の外部保管は MVP では手動とする | 2026-11-04 |
| D23 | 必要な監査ログの追記に失敗した場合、認証の成否を問わず 503 とする。`auth.login` と `auth.password_changed` は業務処理もコミットしない。`auth.login_failed` と `auth.locked` は失敗回数とロックを維持する。`auth.logout` は認証の判定を含まないため、セッションの無効化を優先して 204 とする（[security-design.md §16.5](security-design.md)） | 2026-11-04 |
| D24 | 認証情報を検証できない障害と不一致を区別し、障害を `AUTH_FAILED` として返さない。成功と失敗で監査の失敗の応答に差を設けず、パスワードの正否を判別させない。パスワード変更の不一致にも必須の監査イベント `auth.password_change_failed` を設ける。事前確認で利用できなければ全要求を 503 で拒否する（[security-design.md §16.5.1](security-design.md)） | 2026-11-04 |
| D25 | 匿名イベントの上限は実測に基づかない暫定値として環境変数で設定し、未記録の発生は DB とチェーンに依存しない重大ログで検知し、`audit.events_suppressed` を補助とする。工程1-3の検知は重大ログと終了コードのみとし、通知・メトリクス基盤と `audit:verify` の日次の自動検証は後続工程の候補とする | 2026-11-04 |
| D26 | DB unavailable、Audit unavailable、Redis unavailable を分ける。DB unavailable は確認プローブの `08006` のみで判定する。Audit unavailable は `53100` と設定・権限・スキーマの不備（`42501`、`42883`、`42P01`、`25006`）のみとする。`53100` は DB 全体の書き込みに影響する可能性があるものとして扱い（`storage_scope=db_suspected`）、DB 全体の正常と誤認しない。回復は `audit.availability_checked` の実際の追記で確認する（`outage_id` 単位で最大1件。同一の物理的な障害の単位ではない）。記録済みの判定は DB 関数が診断情報の制約名と行を確認して返す専用の SQLSTATE `SF001` と、PHP の再確認で行い、文字列を解析しない。`55P03`、`57014`、`22023`、未分類のエラーは個別の操作の失敗として扱い、連続回数で全体の状態にしない。`failure_class` で区別する。判定は `PDOException` の `errorInfo[0]` で行い、`getCode()` と Laravel の接続断の判定を使わない。文字列は原因の分類にのみ使う（[security-design.md §16.5.1](security-design.md)） | 2026-11-04 |
| D27 | Redis の停止・接続失敗・タイムアウト時は、Redis に依存する経路を fail closed とし、認証を継続せず RFC 9457 形式の 503 と `Retry-After` を返す。レート制限を無効化して認証を続けない。Redis の状態を記憶せず、要求ごとの接続で復旧を判断する。liveness は止めず、readiness は Redis の状態を反映する。通常の API エラーは RFC 9457 形式とし、readiness のみ工程0の形式を維持する（[security-design.md §16.5.1](security-design.md)） | 2026-11-04 |
| D28 | パスワード変更は DB のコミットを唯一の確定点とし、コミットされた変更は確定として扱う。コミット後に必須のセッションの保存に失敗した場合は、変更を取り消さず 503 を返し、同じキー・同じ内容の再試行を DB の4条件で判定して、再実行せず 200 とする（案 B）。他のセッションの無効化は既存の指紋と DB のハッシュの比較で成立させ、セッションバージョンを追加しない。現在のセッションは、コミット前に保留の指紋を Redis に保存して維持する。再試行は `Idempotency-Key` の HMAC と変更前の Argon2id ハッシュを `users` に保存して防ぎ、要求全体の同一性を判定する（要求指紋の HMAC と専用テーブルとの比較の結果。保留の指紋だけでは認証を許可しない。変更の成否と完了済みのキーの識別は DB の `users` のみで判定し、Redis の情報を根拠にしない）（[security-design.md §16.5.5](security-design.md)） | 2026-11-04 |
| D29 | DB のタイムアウトは、接続、`statement_timeout`、`lock_timeout`、`idle_in_transaction_session_timeout`、TCP keepalive、`tcp_user_timeout` の層に分ける。php-fpm の `request_terminate_timeout` は DB 側のタイムアウトの代替でなく、候補とする。TCP の設定は実際の接続への適用を実装時に確認する。値は暫定値として負荷試験で調整する（[security-design.md §16.5.6](security-design.md)） | 2026-11-04 |
| D30 | 障害中のログは Redis に依存しないローカルの状態で、発生・継続・復旧に集約する。MVP の集約はコンテナの中に限定し、コンテナ間で共有しない（[security-design.md §16.5.7](security-design.md)） | 2026-11-04 |
| D31 | `permanent_config` の Audit unavailable の間は readiness を 200 とする。`storage_scope=db_suspected` の間は readiness を 503、liveness を 200 とし、readiness の 503 で自動再起動しない。監査の障害は `audit.unavailable` のゲージ、状態の変化のログ、`audit:status` で検知し、ログの基盤とアラートの接続を公開環境の前提条件とする（[security-design.md §16.5.1・§16.5.3](security-design.md)） | 2026-11-04 |
| D32 | 行ロックの中の Redis の書き込みは、生のクライアント（`command()` の禁止）、`max_retries=0`、`read_timeout=0.9秒`、ロックの前の `PING` と同一接続の再利用、単調増加時計による全体の期限（1秒）を条件とする。超過は成功扱いにせずロールバックして 503 とする。DB を正とする。WAL 領域の枯渇は `server_panic` として DB unavailable の経路で扱う（[security-design.md §16.5.1・§16.5.5](security-design.md)） | 2026-11-04 |
