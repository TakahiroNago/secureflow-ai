# SecureFlow AI — アーキテクチャ設計書

- 版：v1.2（2026-11-04）
- 状態：確定（v1.2：owner 認証情報の範囲と healthcheck を反映。v1.1：Q-D13・Q-PII・D11・Phase 0 追加条件を反映）
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
│ Audit     : AuditLogger（追記専用・ハッシュチェーン）                    │
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
- **owner ロールの認証情報は `migrate` サービスにのみ渡す。** テスト用DBのスキーマ初期化を行う `test` サービスには、開発用DBに接続できないテスト専用の owner（`secureflow_test_owner`）のみを渡す（[database-design.md §4.3・§4.6](database-design.md)）。`app` / `worker` / `scheduler` のコンテナには owner のパスワードが存在しないため、通常のLaravel実行経路からDDLは実行できない（`php artisan migrate` を app コンテナで実行しても権限不足で失敗する＝fail closed）。
- コンテナイメージは実際に採用したバージョンのタグで固定し、README に記載する。

### 4.1 開発環境

- 開発場所は **WSL2 の Linux ファイルシステム内**（`~/projects/secureflow-ai`）。Windows ドライブ（`/mnt/c`）上には置かない（bind mount の性能とファイル権限のため）。
- Docker Desktop の WSL2 連携を使用する。
- PHP・Composer は**ホストにインストールせず、Docker コンテナ内でのみ実行**する。Node.js もコンテナ内での実行を基本とする。

### 4.2 ヘルスチェック

| エンドポイント | 種別 | 判定 | 応答 |
|---|---|---|---|
| `GET /api/health/live` | Liveness | PHPプロセスが応答できるか（外部依存を確認しない） | 200 `{"status":"ok"}` |
| `GET /api/health/ready` | Readiness | DB（appロールで `SELECT 1`）と Redis（`PING`）に到達できるか | 200 `{"status":"ok"}` ／ 503 `{"status":"unavailable"}` |

応答にはバージョン・ホスト名・接続先・エラー詳細を含めない。失敗の詳細はアプリケーションログにのみ記録する。Docker の healthcheck は nginx・app・worker・scheduler が liveness（DB・Redis に接続しない）、起動順序の制御には postgres・redis 自身の healthcheck を使う。app はソースの存在、php-fpm の応答、Laravel の起動を確認する。worker・scheduler はソースの存在、Laravel の起動、`queue:work` / `schedule:work` の実プロセスを確認し、処理するジョブがないだけでは unhealthy にしない。

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
│  │  ├─ Audit/         (AuditLogger, AuditEventType, HashChain)
│  │  ├─ SelfTest/      (SecuritySelfTestRunner, Cases/*)
│  │  ├─ Jobs/
│  │  └─ Console/Commands/ (user:create, executions:reap-stale, audit:verify)
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
Worker
  5. PromptBuilder：固定システムプロンプト（秘密情報なし・カナリア含む）＋
     ランダム境界文字列で囲んだマスク済み入力（「データとして扱え」と明示）
  6. AiGateway：予算確認 → Provider呼び出し（tools無し、JSON Schema指定、
     max_output_tokens上限、タイムアウト30秒、5xx/429のみ指数バックオフで最大2回）
     → ai_usage_logs 記録（本文は記録しない）
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
| AnalyzeWorkflowJob | `ai` | AI呼び出しはGateway内で最大2回。ジョブ自体は1回 | `ShouldBeUnique`（analysis_request_id） | `failed` に遷移、監査ログ |
| ExecuteWorkflowJob | `execution` | **自動再試行しない**（承認は1回限り消費） | `ShouldBeUnique`（execution_id）＋DB一意制約 | Failed、reopen→再承認が必要 |
| RunSecuritySelfTestJob | `selftest` | なし | 同時に1件のみ | run を failed |
| 停滞回収（scheduler、毎分） | — | — | — | heartbeatがタイムアウトした Running 実行・processing 分析を Failed 化し監査ログ |

ジョブには ID のみを渡す（本文をRedisに載せない）。ジョブ投入はDBコミット後（`afterCommit`）。

## 11. 設定管理（環境変数）

| 変数 | 用途 | 既定 |
|---|---|---|
| `APP_ENV` / `APP_DEBUG` / `APP_KEY` | Laravel標準 | `APP_DEBUG=false`（開発時のみtrue） |
| `DB_*` | 実行用ロール（`secureflow_app`）。app / worker / scheduler に渡す | — |
| `DB_MIGRATOR_*` | マイグレーション用ロール（`secureflow_owner`）。**`migrate` サービスにのみ渡す** | — |
| `REDIS_PASSWORD` | Redis認証 | 必須 |
| `AI_PROVIDER` | `mock` / `openai` | `mock` |
| `OPENAI_API_KEY` | APIキー（画面からは設定不可・表示不可） | 空 |
| `OPENAI_MODEL` | 使用モデル名（Phase 2実装前に確定） | 空 |
| `OPENAI_BASE_URL` | 送信先（固定値。画面から変更不可） | `https://api.openai.com/v1` |
| `AI_TIMEOUT_SECONDS` / `AI_MAX_OUTPUT_TOKENS` | 呼び出し制限 | 30 / 2000 |
| `SESSION_IDLE_MINUTES` / `SESSION_ABSOLUTE_HOURS` | セッション期限 | 30 / 12 |

`AI_PROVIDER=openai` は、Phase 2 でマスキング・出力検証が完成し、必要なセキュリティテスト（[test-strategy.md §5](test-strategy.md) の ST-02〜04, 07, 10, 13〜19, 30, 31, 35〜37）を通過し、D11 の確認が完了するまで受け付けない（起動時の設定検証でエラー）。それまで OpenAiProvider はコード上も登録しない。

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
| D8 | ユーザーは管理コマンド・Seederで作成。公開サインアップなし | 2026-11-03 |
| D9 | Phase 1 はモックAIのみ | 2026-11-03 |
| D10 | Redis を導入 | 2026-11-03 |
| D11 | OpenAIモデル名は環境変数。Phase 2-8 の直前に、モデル・API仕様・データ保持・学習利用・送信データ範囲・レート制限等を確認する。マスキング・出力検証が完成し必要なセキュリティテストを通過するまで実接続を有効化しない | 2026-11-03 |
| D12 | 承認後の編集は Draft に戻し、再提出・再承認を必須とする | 2026-11-03 |
| D13（Q-D13） | 承認できるのは admin のみ。admin は他ユーザーが作成したワークフローのみ承認可能。auditor・member に承認権限なし。申請者と承認者は必ず別ユーザー。承認可能な admin がいなければ実行不可 | 2026-11-03 |
| D14（Q-PII） | 個人情報（メール・電話・カード・マイナンバー等）はマスキング後に続行可。認証・秘密情報（APIキー・トークン・パスワード・秘密鍵/PEM等）は原則停止。severity と action を分離。マスキング失敗時は fail closed。検出限界を画面・APIで明示し、検出漏れがないことを保証しない | 2026-11-03 |
| D15 | 開発場所は WSL2 の Linux ファイルシステム。PHP・Composer はコンテナ内のみ。DBロールは owner / app に分離しマイグレーションは専用経路。DB・Redis ポートは非公開。ヘルスチェックは Liveness / Readiness を分離 | 2026-11-03 |
| D16 | リポジトリは GitHub `TakahiroNago/secureflow-ai`（Public、MIT License） | 2026-11-03 |
