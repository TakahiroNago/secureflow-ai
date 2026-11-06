# SecureFlow AI — 開発ロードマップ

- 版：v1.6（2026-11-06）
- 状態：確定（v1.6：R-19 の対策を公開環境の前提に追加。工程1-5 の範囲、トリガーと監査の時期、未検査の扱い、工程1-6 の決定と要件の期間限定の例外を反映。v1.5：工程1-4 の決定と工程1-6 の条件を反映。v1.4：工程1-3 の範囲を反映。v1.3：工程1-2 の範囲を反映。v1.2：工程1-1 の設計レビューを反映。v1.1：Q-D13・Q-PII・D11・Phase 0 追加条件を反映）

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

**要件の期間限定の例外（工程1-6〜工程2-3。2026-11-06 に承認）：** マスキングは工程2-1 以降のため、編集されたタスクの本文は工程2-3 まで未検査で保存する。`requirements.md` の「入力原文は保存しない」の例外であり、要件自体は変更しない。分析の入力は一切保存しない。本番相当の環境では起動しないため開発環境に限られ、画面に常に警告を表示し、未検査のリビジョンは提出・承認・実行できない。開発用DBにはテストデータのみを入れる（[threat-model.md R-24](threat-model.md)）。**工程2-3 で解消し、延長しない。**

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
| 2-1 | Normalizer、PII/Secret 検出器（ルールごとの severity・action 定義）、Masker、マスキング後再検査（fail closed） | コーパスで目標検出率・誤検知・誤停止が目標内。個人情報は mask_continue、認証・秘密情報は block。マスキング失敗で停止 | Unit、コーパス評価、ST-03, 04, 35, 36 |
| 2-2 | InjectionDetector（ルール・スコアリング） | 4段階判定が仕様どおり | Unit、ST-02, 13, 14, 15 |
| 2-3 | InputScanner 統合、scan-preview API、全体判定（action から算出。D4・D14）、scans/findings 保存、限界文言、`workflow_revisions.scan_id`・`ai_analysis_requests` の検査の列の外部キーと新規行の必須化（工程1-5 の未検査の行は変更しない）、入力と編集内容のマスキングと保存（**工程1-6 の例外の解消**） | block 判定で AI 呼び出し0回。severity と action が別フィールドで返る。限界文言が常に返る | Feature、モック呼出回数検証、ST-39 |
| 2-4 | OutputValidator 拡張（出力マスキング・カナリア・HTML除去・権限照合）、プロンプト構築 | 各モックシナリオで期待どおり | ST-10, 18, 19 |
| 2-5 | 承認API・承認画面（ハッシュ照合・admin のみ・自己承認禁止・リスク確認・承認者不在表示）、submit / reopen、`workflow.submitted`・`workflow.reopened`・`approval.*` の監査記録 | 承認後編集で再承認要求、古いハッシュ 409、自己承認拒否、auditor・member の承認拒否、承認可能な admin 不在で実行不可、未検査のリビジョンの提出・承認の拒否 | ST-06, 09, 16, 17, 20, 21, 37, 38、AUTH-LOCK-03、E2E一部 |
| 2-6 | ExecutionVerifier、ExecuteWorkflowJob、Simulators、冪等性、停滞回収、`execution.*` の監査記録 | 未承認実行拒否、未検査のリビジョンの実行拒否、二重実行なし、障害時 Failed | ST-08, 22, 33、AUTH-LOCK-03、Concurrency |
| 2-7 | 残りのイベントの監査記録（認証と、工程1-6・2-5・2-6 で機能と同時に記録するものを除く。`rate_limit.exceeded` の集約を含む）、検証API（検証器とコマンドは工程1-3）、監査ログ画面（フィルタ） | 全イベント記録、改ざん検出、auditor 参照可・member 403、システムチェーンを API から参照できない | ST-06, 28、AUDIT-SYS-01、Vitest |
| 2-8 | **（実装前に D11 確認：モデル・API仕様・データ保持・学習利用・送信データ範囲・レート制限等。確認結果をレビューに提出）** OpenAiProvider（Structured Outputs、tools無し、タイムアウト、再試行、利用記録、上限）、有効化ゲート（起動時の設定検証） | フェイクHTTPで全エラー系成功。有効化条件（[security-design.md §6.1](security-design.md)）を満たすまで `AI_PROVIDER=openai` が拒否される。条件達成と承認後に実APIで手動確認1回 | ST-30, 31、ゲートのテスト |
| 2-9 | 全体レート制限、セキュリティヘッダ・CSP、エラー形式統一、ログの機密情報除去 | ヘッダ付与、エラーに内部情報なし | ST-11, 29, 32 |
| 2-10 | セキュリティ管理画面（検出一覧・対策状況）、設定画面（APIキー非表示） | キー値が画面・APIに出ない | Feature、Vitest |

## 5. Phase 3：自動セキュリティテスト

| 工程 | 内容 | 完了条件 | テスト方法 |
|---|---|---|---|
| 3-1 | セキュリティテストの分離（ST-01〜34、group: security） | 単独実行で全件成功 | CI security ジョブ |
| 3-2 | 攻撃・正常コーパス整備と評価レポート | レポートを CI で出力 | CI |
| 3-3 | アプリ内自己診断（Runner・API・画面・ダッシュボード表示） | 画面から実行・結果保存・表示 | Feature、E2E |
| 3-4 | Playwright E2E（[test-strategy.md §10](test-strategy.md)） | CI で成功 | CI e2e ジョブ |
| 3-5 | Semgrep（独自ルール：`dangerouslySetInnerHTML`、`DB::raw`、`withoutGlobalScope` 等）、Trivy（fs・イメージ）、composer/npm audit | High 以上の未対応脆弱性なし | CI sast-sca ジョブ |
| 3-6 | README・設計書の最終化、MVP 完成条件の確認 | 要件10の15項目すべて根拠付きで充足 | チェックリスト |

## 6. 要確認事項（実装前に確認）

| ID | 内容 | 確認時期 |
|---|---|---|
| Q-D11 | OpenAI のモデル、API仕様、データ保持、学習利用、送信データ範囲、レート制限等（[security-design.md §6.1](security-design.md)）。確認完了と必要なセキュリティテストの通過まで実接続を有効化しない | Phase 2-8 実装前 |

決定済み：Q-D13（→ D13）、Q-PII（→ D14）。[architecture.md §14](architecture.md) を参照。

## 7. 拡張候補（MVPでは実装しない）

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
| Phase 5：AWS デプロイと監視 | 要件2.2 |
