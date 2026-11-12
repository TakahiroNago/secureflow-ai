# SecureFlow AI — 開発ロードマップ

- 版：v1.18（2026-11-12）
- 状態：確定（v1.18：Phase 5（AWS デプロイと監視）の工程を §8 に追加し、工程5-1 の完了を反映。v1.17：工程3-6 の完了（MVP 完成）を反映。v1.16：工程3-2 の範囲を反映。v1.15：工程3-4 の範囲を反映。v1.14：工程3-3 の範囲を反映。v1.13：工程3-1・3-5 の範囲を反映。v1.12：工程2-10 の範囲を反映。v1.11：工程2-9 の範囲を反映。v1.10：D11 の確認の完了を反映。v1.9：工程2-7 の範囲を反映。v1.8：工程2-6 の範囲を反映。v1.7：工程2-5 の完了条件に未検査の拒否の応答と計画の照合を反映。v1.6：R-19 の対策を公開環境の前提に追加。工程1-5 の範囲、トリガーと監査の時期、未検査の扱い、工程1-6 の決定と要件の期間限定の例外を反映。v1.5：工程1-4 の決定と工程1-6 の条件を反映。v1.4：工程1-3 の範囲を反映。v1.3：工程1-2 の範囲を反映。v1.2：工程1-1 の設計レビューを反映。v1.1：Q-D13・Q-PII・D11・Phase 0 追加条件を反映）

---

## 1. 進め方

- Phase 単位で実装し、各 Phase の完了時に以下を報告してレビューを受ける：実装した機能／変更したファイル／実施したテスト／テスト結果／セキュリティ上の確認事項／残っている課題／次の Phase。
- 各工程（例 1-2）はテストを含めて完了させてから次へ進む。
- 設計からの逸脱が必要になった場合は、実装前に理由と代替案を提示する。

## 2. Phase 0：開発基盤

**前提（D15・D16）：** 開発場所は WSL2 の Linux ファイルシステム（`~/projects/secureflow-ai`）。Docker Desktop の WSL2 連携を使用し、PHP・Composer はコンテナ内でのみ実行する。リポジトリは GitHub `TakahiroNago/secureflow-ai`（Public、MIT License）。各工程は完了条件を満たしてからコミットし、壊れた状態をコミットしない。

| 工程 | 内容 | 完了条件 | テスト方法 |
|---|---|---|---|
| 0-1 | Git 初期化、`.gitignore`、`.gitattributes`、`.editorconfig`、`.env.example`、`LICENSE`（MIT）、設計書（v1.1）の登録 | `.env` が追跡対象外。`.env.example` はダミー値のみ。秘密情報スキャンで検出0件 | `git check-ignore`、`git status`、gitleaks（コンテナで実行） |
| 0-2 | Docker Compose の基盤：`postgres`（初期化スクリプトで owner / app ロール・開発用DB・テスト用DB作成）、`redis`（パスワード必須）、PHP イメージ（Dockerfile）のビルド | postgres・redis が healthy。ホストに DB・Redis ポートが公開されていない。ロール属性・権限が設計どおり。PHP イメージがビルドでき、拡張が揃っている。採用バージョンをタグで固定 | P0-DB-03、P0-NET-01、P0-NET-02、`docker compose ps` |
| 0-3 | Laravel 雛形（コンテナ内の Composer で作成）、Sanctum、Pest、Larastan、Pint、DB接続2系統（app / migrator）、Redis 設定、`app` / `worker` / `scheduler` / `migrate` / `nginx` サービス、Liveness / Readiness | live・ready が仕様どおり。app ロールで DDL 不可、migrate 経路で成功。Pest・Larastan・Pint 成功 | P0-HC-01、P0-HC-02、P0-DB-01、P0-DB-02 |
| 0-4 | React 雛形（Vite + TS + Tailwind）、ESLint（`no-restricted-syntax` で `dangerouslySetInnerHTML`・`innerHTML` 等を error）、Vitest、`frontend` サービス、nginx からの配信 | 画面表示、Vite proxy で live ヘルスチェック取得。Lint・型・テスト・ビルド成功 | P0-FE-01 |
| 0-5 | GitHub Actions（secret-scan：gitleaks・Trivy／backend・frontend：Lint・型・テスト・ビルド）、GitHub リポジトリ作成と初回 push（push 前に秘密情報・個人情報・不要ファイルを確認） | GitHub 上で CI 成功 | Actions 実行結果、P0-SEC-01 |
| 0-6 | README（セットアップ・アーキテクチャ概要・**採用バージョン一覧**・ヘルスチェック・マイグレーション手順） | 新しいクローンから README の手順どおりに起動・テストできる | 手順の再現確認 |

**Phase 0 完了条件：** クリーンな状態から README の手順で起動でき、Liveness / Readiness・全Lint・全テスト・CI が成功し、`.env` と秘密情報がリポジトリに含まれず、DB ロールが分離されている。

## 3. Phase 1：基本アプリケーションとAIワークフロー（モックAIのみ：D9）

**要件の期間限定の例外（工程1-6〜工程2-3。2026-11-06 に承認）は工程2-3 で解消した。** 編集されたタスクの本文を未検査で保存していたものである。工程2-3 以降はマスク済みの文のみ保存する。**工程2-3 より前に保存された行は追記専用のため残る**（開発用DBのテストデータのみ。未検査のまま扱い、提出・承認・実行できない。[threat-model.md R-24](threat-model.md)）。

| 工程 | 内容 | 完了条件 | テスト方法 |
|---|---|---|---|
| 1-1 | organizations / organization_settings / users / audit_logs マイグレーション（チェーン用の列は工程1-3で追加）、DB権限・改変拒否トリガー、テスト用DBのガードと破壊的コマンドの制限（[database-design.md §4.5・§4.6](database-design.md)）、`tests/Security` の `Pest.php`・`phpunit.xml` への登録 | migrate / rollback 成功。app ロールで audit_logs の UPDATE/DELETE が失敗し、`id` 指定の INSERT と `nextval()` が拒否される。テスト用DB以外で破壊的操作を実行できない | マイグレーションテスト、ST-28（DB部分）、[test-strategy.md §13](test-strategy.md) |
| 1-2 | 認証API（`PATCH /account/password` を含む）・ログイン画面・セッション管理・ロック・`user:create` コマンド・Seeder（組織や初期設定のみ。ログイン可能な固定ユーザーは生成しない）、Argon2id の設定、漏洩パスワード辞書、`User` モデルと Factory の設計どおりの修正（`HasUuids` を含む）。認証イベントの監査記録は工程1-3 | ログイン/ログアウト可、未認証 401、失敗は 401 `AUTH_FAILED`、6回目 429、ロック動作（既存セッションは維持）、`is_active=false` で即時無効化、パスワード変更で他のセッションのみ無効化 | Feature、ST-05, 24, 25, 26, 27、[test-strategy.md §14](test-strategy.md)、Vitest |
| 1-3 | `audit_chain_heads`、`audit_logs` のチェーン用の列・制約・インデックス・権限、SECURITY DEFINER 関数 `audit_append()`、組織チェーンとシステムチェーン、AuditLogger、認証イベント記録（[security-design.md §16.5](security-design.md)）、監査の事前確認と3つの状態の分離（DB unavailable は確認プローブ、Audit unavailable は実際の追記で回復を確認。文字列で判定しない）、`audit.unavailable` のログと `audit:status`、readiness の実装と `README.md` のヘルスチェックの説明の更新、Redis 障害時の fail closed（RFC 9457 形式の 503）、パスワード変更の確定と再試行（`users.password_change_key_hash`、`users.password_change_previous_hash`）、DB のタイムアウトの層、障害中のログの集約、PHP の検証器、`audit:verify`（手動実行）、`audit:head`（外部保管は手動）、匿名イベントの上限（暫定値・環境変数で変更可）と未記録の検知。**開発用DBへの適用前に、工程1-1適用後・Seeder 実行後のバックアップを取得する**（[database-design.md §4.5](database-design.md)） | app ロールで直接追記できない。記録にパスワード等が含まれない。チェーン検証成功。PHP と PostgreSQL が固定テストベクトルを再現する。改ざんを検出し、検出できない範囲がテストで明示されている。記録の失敗時の動作がイベントごとの設計どおりで、監査が利用できないときの応答から認証情報の正否を区別できない。監査の失敗時の応答からパスワードの正否を判別できないことをテストで確認している。暫定値の負荷試験の結果を報告している | Unit、ST-28、[test-strategy.md §15](test-strategy.md) |
| 1-4 | ActionCatalog、AiProvider、MockAiProvider、AiGateway（モック）、OutputValidator（スキーマ・許可リスト） | 不正JSON・未知キー・未知操作を拒否、forbidden 判定 | Unit（§4 のモックシナリオ）、ST-07 |
| 1-5 | workflows / revisions / tasks / approvals / executions マイグレーション（複合外部キー、列単位の権限、改変拒否、**自己承認禁止・admin 必須のトリガー**）、StateMachine、PlanHasher、Policy、組織スコープ。**API はないため、HTTP の応答はテスト専用のルートで確認する** | 不正遷移 409、他人データ 404、ハッシュ仕様どおり | Unit（遷移全組合せ、正規化）、Isolation、Concurrency、ST-12, 34、ST-21・ST-38（DB 部分）、ST-23（モデルと Policy） |
| 1-6 | ai_analysis_requests、`failed_jobs`（テーブルと権限）、AnalyzeWorkflowJob（モック）、ワークフローAPI・画面（入力・分析・表示・編集・保存）。**ジョブの時間制限は `AiGateway::worstCaseSeconds()`（既定値で93秒）より長くする。worker の `--timeout`（現在は未指定で既定の60秒）とキューの `retry_after` もこれに合わせて見直す**。`workflow.created`・`workflow.updated`・`analysis.failed` の監査記録、DB キューへの移行、停滞回収 | 入力→生成→編集→保存。編集で新リビジョン。再試行の途中でジョブが打ち切られない。状態変更が監査と同じトランザクションで記録される | Feature、Vitest、ST-23（全エンドポイント） |
| 1-7 | ダッシュボード（基本KPI、状態別のグラフ、最近の操作）。データのない項目は工程2-3、2-8、3-3 まで未実装と表示する（0 としない） | 集計値が正しい（ロール別範囲） | Feature（固定データ）、Vitest、実ブラウザ |

## 4. Phase 2：セキュリティ制御と監査ログ

| 工程 | 内容 | 完了条件 | テスト方法 |
|---|---|---|---|
| 2-1 | Normalizer、PII/Secret 検出器（ルールごとの severity・action 定義）、Masker、マスキング後再検査（fail closed）。**検査の部品のみで、API と処理への組み込みは工程2-3** | コーパスで目標検出率・誤検知・誤停止が目標内。個人情報は mask_continue、認証・秘密情報は block。マスキング失敗で停止 | Unit、コーパス評価、ST-36、ST-03, 04, 35（部品の部分） |
| 2-2 | InjectionDetector（ルール・スコアリング）。**検査の部品のみで、処理への組み込みは工程2-3、カナリアは工程2-4** | 4段階判定が仕様どおり。**検出率は調整用 99.2%、評価専用 3.6%（目標 90% は調整用のみ達成）** | Unit、コーパス評価、ST-02, 13, 14（部品の部分） |
| 2-3 | InputScanner 統合、scan-preview API、全体判定（action から算出。D4・D14）、scans/findings 保存、限界文言、`workflow_revisions.scan_id`・`ai_analysis_requests` の検査の列の外部キーと新規行の必須化（工程1-5 の未検査の行は変更しない）、入力と編集内容のマスキングと保存（**工程1-6 の例外の解消**）、AI の出力の検査（秘密情報・個人情報・インジェクション。カナリアと HTML 除去は工程2-4）、`security.scan`・`security.blocked` の監査記録 | block 判定で AI 呼び出し0回。severity と action が別フィールドで返る。限界文言が常に返る。原文が全テーブル・ログ・キューに残らない | Feature、モック呼出回数検証、ST-39 |
| 2-4 | OutputScanner（出力マスキング・カナリア・HTML除去・権限照合・禁止操作の記録）、PromptBuilder（固定テンプレート、カナリア、境界）。工程2-3 の `requested_permissions` の未検査の修正 | 各モックシナリオで期待どおり。カナリアとマークアップで隠せない。**プロンプトの実 AI での効果は工程2-8 で確認** | ST-10, 15, 18, 19 |
| 2-5 | 承認API・承認画面（ハッシュ照合・admin のみ・自己承認禁止・リスク確認・承認者不在表示）、submit / reopen、`workflow.submitted`・`workflow.reopened`・`approval.*` の監査記録 | 承認後編集で再承認要求、古いハッシュ 409、自己承認拒否、auditor・member の承認拒否、承認可能な admin 不在で実行不可、未検査のリビジョンの提出・承認の拒否（409 `SCAN_REQUIRED`）、保存済みの計画の照合、コメントと却下の理由の検査 | ST-06, 09, 16, 17, 20, 21, 37, 38、AUTH-LOCK-03、E2E一部 |
| 2-6 | ExecutionVerifier、ExecuteWorkflowJob、Simulators、冪等性、停滞回収、`execution.*` の監査記録 | 未承認実行拒否、未検査のリビジョンの実行拒否、二重実行なし、障害時 Failed（worker の実際の強制終了で確認） | ST-08, 22, 33、AUTH-LOCK-03、Concurrency |
| 2-7 | 残りのイベントの監査記録（認証と、工程1-6・2-3・2-5・2-6 で機能と同時に記録するものを除く。`rate_limit.exceeded` の集約を含む）、検証API（検証器とコマンドは工程1-3）、監査ログ画面（フィルタ） | 全イベント記録（**機能がまだない `finding.status_changed`、`settings.updated`、`selftest.*` と、`ai.call` の上限超過を除く。** 工程2-8、2-10、3-3 で機能と同時に記録する）、改ざん検出、auditor 参照可・member 403、システムチェーンを API から参照できない | ST-06, 28、AUDIT-SYS-01、Vitest |
| 2-8 | **（実装前に D11 確認：モデル・API仕様・データ保持・学習利用・送信データ範囲・レート制限等。確認結果をレビューに提出）** OpenAiProvider（Structured Outputs、tools無し、タイムアウト、再試行、利用記録、上限）、有効化ゲート（起動時の設定検証） | フェイクHTTPで全エラー系成功。有効化条件（[security-design.md §6.1](security-design.md)）を満たすまで `AI_PROVIDER=openai` が拒否される。条件達成と承認後に実APIで手動確認1回 | ST-30, 31、ゲートのテスト |
| 2-9 | 全体レート制限、セキュリティヘッダ・CSP、エラー形式統一、ログの機密情報除去 | ヘッダ付与、エラーに内部情報なし、ログに機密情報なし（nginx 自身の応答を含む） | ST-11, 29, 32 |
| 2-10 | セキュリティ管理画面（検出一覧・対策状況・検査の詳細。自己診断の結果は工程3-3 まで未実装と表示）、設定画面（AI の設定の参照、利用上限の変更、セキュリティ設定の参照、パスワードの変更）、`finding.status_changed`・`settings.updated` の監査記録 | キー値が画面・APIに出ない。対策状況の変更は admin のみで、メモは検査してマスク済みのみ保存し、変更は監査と同じトランザクションで記録する。上限の変更が直ちに効く | Feature、Vitest（[test-strategy.md §30](test-strategy.md)） |

## 5. Phase 3：自動セキュリティテスト

| 工程 | 内容 | 完了条件 | テスト方法 |
|---|---|---|---|
| 3-1 | セキュリティテストの分離（ST-01〜39 を `security` グループに。ファイルの場所は変えず、全件の存在を自動検査）、コーパス評価レポート（`security:corpus-report`。調整用と評価専用を併記）、バックエンドのカバレッジの計測と目標の確認（基準値 96.7%）、フロントエンドのカバレッジ（`@vitest/coverage-v8`。基準値 94.8%、しきい値 70%） | `pest --group security` の単独実行で全件成功。レポートが CI のサマリと artifact に出る。カバレッジが §3 の目標を満たす | CI security ジョブ、backend ジョブ（[test-strategy.md §31](test-strategy.md)） |
| 3-2 | 英語の業務文コーパス（`business-en.json`。報告のみ、合否にしない）、評価集合（`resources/security/evaluation/requests.json`：正常 20・攻撃 15）、評価コマンド `ai:evaluate`（実際の経路で処理し、段階・操作・権限・検出・指示に従った兆候・利用記録を本文なしで出力。モックは `--mock`）、`scripts/evaluate-ai.sh`（使い捨ての環境で実プロバイダ）。**実 AI の評価（複数の依頼文での操作の選択と権限の申告、攻撃文への耐性 R-26）は承認を得て手動で行い、[test-strategy.md §34](test-strategy.md) に記録する（2026-11-08 に実施：正常 19/20、権限 20/20、攻撃 12 文到達で開示・漏洩なし、従ったのは言語の変更など 2 件）。`db.query` は禁止のまま変えず、集計の依頼で選ばれる頻度を記録する** | レポートを CI で出力。評価コマンドがモックで試験されている。実 AI の評価を実施し、結果を記録する | CI、AI-EVAL-01、手動 |
| 3-3 | アプリ内自己診断：§5 の「自己診断 ○」26 ケースを判定部品とサービス層で確認する Runner（各ケースをロールバック、AI はモック固定）、`security_test_runs` / `security_test_results`、`RunSecuritySelfTestJob`（キュー `selftest`、組織ごとに同時 1 件）、`selftest:recover`、API 3 本、セキュリティ管理画面とダッシュボードの表示、`selftest.started`・`selftest.completed` | 画面から実行でき、結果が保存・表示される。全ケースが現行コードで合格し、作った行が残らない。CI のみのケースを画面に示す | Feature、Vitest（[test-strategy.md §32](test-strategy.md)）。実ブラウザは工程3-4 |
| 3-4 | Playwright E2E（[test-strategy.md §10](test-strategy.md)）：`e2e/` のプロジェクト（§10 の 1〜11 を 3 ブラウザ、承認後編集の再承認・同時 2 回の実行要求・自己診断・セキュリティ管理と設定・ロールごとの表示を Chromium）、`scripts/test-e2e.sh`、CI の `e2e` ジョブ（画面の保存と失敗のトレースを artifact に）。stack ジョブの実ブラウザの段階を移した | CI で成功 | CI e2e ジョブ（[test-strategy.md §33](test-strategy.md)） |
| 3-5 | Semgrep（独自ルールのみ `.semgrep/secureflow.yml`：生 SQL、`withoutGlobalScope`、コード実行、TLS 検証の無効化、ミドルウェアの除外、AI への `tools`、HTML の描画。ルール自体の負のテスト付き）、Trivy（fs と、PHP イメージ・固定済みの全イメージ。HIGH 以上で修正版のあるものは失敗。例外は `.trivyignore.yaml` に理由と期限。初回は node イメージ同梱の npm に 6 件、期限付きで除外）。composer/npm audit は backend/frontend ジョブのまま | High 以上の未対応脆弱性なし。許可した 4 箇所以外に Semgrep の検出なし | CI sast-sca ジョブ（[test-strategy.md §31](test-strategy.md)） |
| 3-6 | README・設計書の最終化、MVP 完成条件の確認（[mvp-completion.md](mvp-completion.md)：要件10 の 15 項目を実装箇所・自動テスト・CI・開発環境での確認で裏付け、全テストの最終計測を記録）、公開環境への移行の前提条件の集約（[security-design.md §22](security-design.md)）、README の状態行と採用バージョンの照合 | 要件10の15項目すべて根拠付きで充足（**2026-11-08 に確認。MVP 完成**） | チェックリスト（[mvp-completion.md](mvp-completion.md)） |

## 6. 要確認事項（実装前に確認）

| ID | 内容 | 確認時期 |
|---|---|---|
| Q-D11 | **確認済み（2026-11-07）。** OpenAI のモデル、API仕様、データ保持、学習利用、送信データ範囲、レート制限等（[security-design.md §6.1](security-design.md)）。必要なセキュリティテストの通過まで実接続を有効化しない。公開環境の前にデータ保持と検出率を再評価する | Phase 2-8 実装前 |

決定済み：Q-D13（→ D13）、Q-PII（→ D14）。[architecture.md §14](architecture.md) を参照。

## 7. 拡張候補（MVPでは実装しない）

公開環境へ移行する前に満たす条件（下表の「公開環境の前提」）は [security-design.md §22](security-design.md) に集約した。Phase 5 の工程は §8 にあり、下表の該当行はそこで扱う。

| 候補 | 関連 |
|---|---|
| 監査ログハッシュの外部ストレージへの自動退避（S3 Object Lock 等）。MVP は `audit:head` の手動保管 | 監査ログ完全性（R-03） |
| `audit:verify` の日次の自動検証（工程1-3は手動実行） | 監査ログ完全性（R-16） |
| 通知・メトリクス基盤（`metric=` のログの集計、記録の失敗・抑制・検証の失敗の通知）。工程1-3は重大ログと終了コードのみで、ログを確認しなければ検知できない | Phase 5 の監視（R-16） |
| 監査イベントを確実に残す方式（トランザクションアウトボックス等） | 別トランザクションの記録の欠落（R-13） |
| 匿名イベントの上限の確定（公開環境の構成が決まった時点で再測定） | R-12、R-17 |
| **信頼できるリバースプロキシと接続元 IP の取得方法の確定（公開環境の前提。IP 単位の制限が正しく動作するまで公開環境へ移行しない）** | 送信元 IP（R-17） |
| **DB のプロセスの無応答によるワーカーの枯渇への対策（公開環境の前提。対策するまで公開環境へ移行しない）：** php-fpm の `request_terminate_timeout`（候補30秒）と nginx の応答の変換、ワーカーの空きを確認する healthcheck。測定結果は [test-strategy.md §17.2](test-strategy.md) | R-19 |
| WAL 領域の枯渇からの具体的な復旧手順（運用設計） | R-18 |
| **ログの基盤と `audit.unavailable` のアラートの接続（公開環境の前提）。** readiness では監査の障害を区別できないため。**readiness はトラフィックの制御のみ、liveness は再起動の判断のみに使う** | R-16 |
| 複数の app コンテナでの DB unavailable・Audit unavailable と、ログの集約の共有 | R-18、R-22 |
| パスワード変更の冪等性の専用テーブルへの移行（他の API との共通化、失敗の再現が必要になった場合） | [security-design.md §16.5.5](security-design.md) |
| DB のプロセスの無応答の検知（監視、自動の切り替え） | R-19 |
| Redis の障害時のセッションとカウンタの扱い（永続化、冗長化） | R-20 |
| PostgreSQL 行レベルセキュリティ（RLS） | データ分離の多層化 |
| MFA、パスワードリセット | 認証強化 |
| AIによるインジェクション追加判定（リスク引き上げ専用） | 検出精度 |
| 氏名・住所等の固有表現検出 | 個人情報検出の限界（R-02） |
| CI テスト結果のアプリ取り込み | D6 |
| 保持期間経過データの安全な削除手順 | データ保持 |
| Phase 4：外部サービス連携（操作カタログ＋専用ハンドラ＋承認必須の形でのみ） | 要件2.2 |
| Phase 5：AWS デプロイと監視 | 要件2.2。**§8 で実施中（2026-11-12 着手）** |

## 8. Phase 5：AWS デプロイと監視（2026-11-12 着手）

設計の判断（構成 1〜10）は [architecture.md §14](architecture.md) の D33〜D35 と [operations.md §1](operations.md) にある。Phase 4（外部連携）は先に行わない：実行は模擬のみで、公開環境でも外部への操作は起きない。

| 工程 | 内容 | 完了条件 | テスト方法 |
|---|---|---|---|
| 5-1 | 本番用イメージ（`docker/php/Dockerfile` の `prod`、`docker/nginx/Dockerfile`）、`compose.prod.yaml`（バインドマウントなし、`web` も internal、nginx のみ `edge`）、nginx の `real_ip` と HSTS、php-fpm の `request_terminate_timeout` と空きワーカーの healthcheck、`mock` の本番相当の環境での起動、`organization:create`（本番では `db:seed` を使えないため）、`scripts/prod/`（deploy、fetch-env、backup、restore、audit-anchor、check、systemd のタイマー）、`scripts/test-prod-stack.sh`、CI の `prod-stack` ジョブと `Release` ワークフロー、[operations.md](operations.md) | CI 全緑。本番の形のスタックが CI で起動し PROD-01〜06 に合格する（**2026-11-12 実装**） | CI prod-stack ジョブ（[test-strategy.md §36](test-strategy.md)） |
| 5-2 | Terraform（`infra/aws/`）：VPC、セキュリティグループ、EC2（SSM、初回起動で Docker と awslogs、リポジトリとタイマー）、ALB + ACM（HTTP→HTTPS）、S3（バージョニング、暗号化、ホストのロールは put/get のみ）、Parameter Store、CloudWatch Logs のフィルタとアラーム、SNS、Budget。apply は運用者 | 運用者の apply が成功し、ALB が `/api/health/live` を 200 で見る | 手動（apply の結果と `scripts/prod/check.sh`） |
| 5-3 | DNS 切替前の検証と §22 B の再測定：別の 2 つの接続元での IP 単位の制限（A-2）、実際の DB の無応答（A-3）、復元試験、負荷の再測定、アラートの実発報 | 結果を [security-design.md §22](security-design.md) と [test-strategy.md](test-strategy.md) に記録し、A-1〜A-4 を「満たした」に更新する | 手動（[operations.md §5](operations.md)） |
| 5-4 | 公開：DNS の切替、admin 2 名の作成、画面の自己診断、`audit:verify`、README とポートフォリオの更新 | 公開環境で自己診断が全件合格し、チェーンが検証できる | 手動 |
| 5-5 | （任意）OpenAI の有効化：A-5 の再評価（ZDR、検出率、送信先）を §6.1 に記し、`AiConfiguration` の本番相当の環境での `openai` の拒否を外す | §6.1 に結論があり、`ai:evaluate` を公開環境相当で再実施している | AI-CONF-01、AI-EVAL-01 |
