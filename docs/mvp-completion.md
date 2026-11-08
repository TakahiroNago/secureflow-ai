# SecureFlow AI — MVP 完成条件の確認

- 版：v1.0（2026-11-08）
- 状態：確定（工程3-6。[requirements.md §10](requirements.md) の 15 項目を、実装箇所・自動テスト・CI・開発環境での確認で裏付ける）
- 関連：[development-roadmap.md](development-roadmap.md) / [test-strategy.md](test-strategy.md) / [security-design.md §22](security-design.md)（公開環境への移行の前提条件）

---

## 1. 判定

**要件10 の 15 項目をすべて満たし、MVP を完成とする（2026-11-08）。** 判定の根拠は §3 の表のとおりで、各項目に実装箇所、自動テスト、CI のジョブ、開発環境での確認の 4 つを付ける。数値は §2 の計測のもので、計測の日付と環境を伴わない数値は根拠にしない。

MVP の範囲外（[requirements.md §11](requirements.md)、[development-roadmap.md §7](development-roadmap.md)）と、公開環境へ移行する前に満たす条件（[security-design.md §22](security-design.md)）は、完成の判定に含めない。**この MVP は開発環境で動作するものであり、公開環境で動作する状態ではない。**

## 2. 計測（2026-11-08、隔離クローン `secureflow-check`、main 5ed2287）

| 計測 | 結果 | 方法 |
|---|---|---|
| Pest（全件） | 2,168 件成功、失敗 0（ほかに警告 3 件：不正な正規表現と存在しないファイルを与える意図した失敗経路のテストが PHP の警告を出すもので、いずれも成功） | `docker compose run --rm test` |
| Pest `security` グループ | 440 件成功、失敗 0（ST-01〜39 とコーパスの合否） | `pest --group security` |
| コーパス評価 | 合否のある指標はすべて目標内。評価専用の検出率 3.6% と英語の業務文は報告のみ（[test-strategy.md §7](test-strategy.md)） | `security:corpus-report` |
| 評価コマンド（モック） | 35 文すべて処理（正常 20・攻撃 15。呼び出し 32、入力検査で停止 3） | `ai:evaluate --mock` |
| Vitest | 144 件成功、行カバレッジ 95.2%（しきい値 70%） | `npm run test:coverage` |
| ESLint / tsc / ビルド | 誤りなし | `npm run lint`、`npm run typecheck`、`npm run build` |
| Pint / Larastan（レベル 8） | 誤りなし | `pint --test`、`phpstan analyse` |
| Semgrep（独自ルール） | 検出 0 件。ルールの負のテスト 8 / 8 | `scripts/test-semgrep-rules.sh`、`semgrep scan` |
| Trivy（fs） | CI と同じ範囲（`vendor`・`node_modules`・E2E の出力を除く）で 0 件。クローンの作業ツリー全体では `backend/vendor` 内の開発依存に同梱された見本の Dockerfile に DS-0029（HIGH、`--no-install-recommends` なし）が 1 件出るが、アプリに含まれず CI の走査対象でもない | `trivy fs`（例外は `.trivyignore.yaml`、期限 2026-12-07） |
| 基盤の検証 | 成功 | `scripts/verify-infra.sh` |
| E2E（Playwright） | 8 件成功（1.4 分）（Chromium・Firefox・WebKit） | `scripts/test-e2e.sh` |
| アプリ内の自己診断 | 26 / 26 合格（E2E の中で画面から実行。`security_test_runs` に total 26・passed 26・failed 0、ruleset 2026.11.1/2026.11.2、policy 2026.11.1） | `self-test.spec.ts` |
| CI（main、5ed2287） | 7 ジョブすべて成功（[実行 42470700770](https://github.com/TakahiroNago/secureflow-ai/actions/runs/42470700770)） | GitHub Actions |

開発環境（WSL2 の `~/projects/secureflow-ai`、プロジェクト `secureflow`）は main と同じコミットで動作し、利用者（管理者）が画面で確認した項目は §3 に日付を付けて記す。

## 3. 要件10 の 15 項目と根拠

| # | 完成条件 | 実装箇所 | 自動テスト | CI | 開発環境での確認 | 判定 |
|---|---|---|---|---|---|---|
| 1 | Docker Compose でローカル起動できる | `compose.yaml`（postgres、redis、app、worker、scheduler、nginx、frontend。migrate と test は都度実行、`ai-egress` は profile）、`docker/`、`scripts/init-env.sh`、README「セットアップ」 | P0-HC-01・02、P0-DB-01〜03、P0-NET-01・02（[test-strategy.md §12](test-strategy.md)）、`scripts/verify-infra.sh` | Full stack（`compose up --wait`、マイグレーション、`verify-infra.sh`、公開ポートと healthcheck の負のテスト） | README の手順で起動した環境が 2026-11-05 から動作。隔離クローンも同じ手順で作成 | 充足 |
| 2 | ユーザー認証が動作する | Sanctum の SPA Cookie 認証、`user:create`、Argon2id、ロック、セッション ID の再生成、パスワード変更（[security-design.md §12](security-design.md)） | ST-05、24〜27、AUTH-*（[test-strategy.md §14](test-strategy.md)）、ST-34（全ルートの認可）、E2E `main-flow`・`roles` | Backend、Security tests、Full stack（認証の通し確認）、E2E | 2026-11-05 に画面でログインとログアウトを確認 | 充足 |
| 3 | AI による文章分析が動作する | `AnalysisService`、`AnalyzeWorkflowJob`、`AnalysisProcessor`、`PromptBuilder`、`AiGateway`、`MockAiProvider` / `OpenAiProvider`（[architecture.md](architecture.md)） | ST-01、07、30、31、モックのシナリオ（§4）、[test-strategy.md §19・§28](test-strategy.md)、AI-EVAL-01 | Backend、Security tests、E2E（モック） | 2026-11-07 に画面で生成から提出・承認までを確認。実プロバイダは 2026-11-07（1 文 2 回）と 2026-11-08（35 文、[test-strategy.md §34](test-strategy.md)）に隔離クローンで確認 | 充足 |
| 4 | タスクがデータベースに保存される | `workflows`、`workflow_revisions`、`workflow_tasks`（[database-design.md §3](database-design.md)）、`WorkflowCreator` | [test-strategy.md §18・§19](test-strategy.md)、ST-23（全エンドポイントの組織分離）、Isolation | Backend | 開発環境の DB に生成・編集・承認・実行まで進んだワークフローの行がある（2026-11-07） | 充足 |
| 5 | プロンプトインジェクション検査が動作する | `InjectionScanner`（ルールとスコア）、`InputScanner`、難読化の正規化、カナリア（[security-design.md §3.5・§5](security-design.md)） | ST-02、13、14、15、コーパスの合否（調整用 121 / 122。評価専用 2 / 55 は報告のみ）、[test-strategy.md §22・§23](test-strategy.md) | Security tests（コーパスレポートを artifact に）、Backend | 2026-11-08 の自己診断（ST-02、13、14、15 を含む）が開発環境で 26 / 26 合格。限界は画面と README に明記 | 充足（検出は補助層。R-01） |
| 6 | 個人情報・機密情報のマスキングが動作する | PII / Secret 検出器、`Masker`、再検査の fail closed、出力のマスキング（[security-design.md §3.3・§3.4・§7](security-design.md)） | ST-03、04、19、35、36、コーパス（形式のある機密情報 100%、業務文の誤停止 0）、[test-strategy.md §21](test-strategy.md) | Security tests、Backend | 2026-11-08 の自己診断（ST-03、04、19、35、36 を含む）が開発環境で 26 / 26 合格 | 充足（氏名・住所は検出しない。R-02） |
| 7 | AI の権限が制限されている | `tools` を送らない（ST-31）、`ActionCatalog` の許可リスト、権限のサーバー導出（`derived_permissions`）、禁止操作のハンドラが存在しない、worker は内部ネットワークのみ（[security-design.md §6・§8・§10](security-design.md)） | ST-16、17、18、31、Semgrep ルール（AI への `tools`、コード実行）、AI-EVAL-01 | Backend、SAST / SCA | 実プロバイダの評価（2026-11-08）で、外部への操作を求める 5 文がすべて禁止操作として見せられ、提出で拒否される経路を確認 | 充足 |
| 8 | 承認前に処理が実行されない | `ExecutionVerifier`（承認ハッシュ・承認者の正当性・リビジョンの照合）、`approvals` のトリガー（自己承認禁止・admin 必須）（[security-design.md §9・§10](security-design.md)） | ST-08、20、21、37、38、[test-strategy.md §25・§26](test-strategy.md)、E2E `main-flow`（member は承認できない） | Backend、Security tests、E2E | 2026-11-08 の自己診断（ST-08、20、21、37、38 を含む）が開発環境で合格。2026-11-07 に画面で別の admin による承認と、その後の実行を確認 | 充足 |
| 9 | 承認後の内容変更で再承認が必要になる | `StateMachine`（承認後の編集で Draft に戻る）、`plan_hash` の照合（[security-design.md §9](security-design.md)） | ST-09、20、E2E `reapproval` | Backend、Security tests、E2E | 2026-11-08 の自己診断（ST-09 を含む）が開発環境で合格 | 充足 |
| 10 | 模擬実行が正常に動作する | `ExecuteWorkflowJob`、`Simulators`（外部への操作は行わない）、冪等性キー、停滞回収（[architecture.md §10](architecture.md)） | ST-22、33（worker の実際の強制終了）、Concurrency、E2E `double-execution`・`main-flow` | Backend、Security tests、E2E | 2026-11-07 に画面で実行と結果の保存を確認 | 充足 |
| 11 | 監査ログが記録される | `audit_append()`、組織とシステムのハッシュチェーン、改変拒否トリガー、`audit:verify` / `audit:head`、監査ログ画面（[security-design.md §16](security-design.md)、[database-design.md §3.12](database-design.md)） | ST-28、[test-strategy.md §15・§27](test-strategy.md)、AUDIT-LOAD-01（§17） | Backend、Security tests、E2E（監査ログの閲覧） | 開発環境のチェーンは各工程の反映の前後で変わらず、2026-11-08 に `audit:verify --all` が成功 | 充足 |
| 12 | セキュリティテストが実行できる | `pest --group security`（ST-01〜39、ST-GROUP-01）、アプリ内の自己診断（26 ケース、セキュリティ管理画面）、`security:corpus-report`、`ai:evaluate` | ST-GROUP-01、[test-strategy.md §32](test-strategy.md)（自己診断）、E2E `self-test` | Security tests、SAST / SCA、Secret scan | 2026-11-08 に画面から自己診断を実行し 26 / 26 合格 | 充足 |
| 13 | テストが成功する | — | §2 のとおり全件成功 | 5ed2287 の CI で全ジョブ成功 | — | 充足 |
| 14 | GitHub Actions が正常に動作する | `.github/workflows/ci.yml`（7 ジョブ。権限は `contents: read`、使い捨ての `.env`、実際の AI キーは使わない） | — | [実行 42470700770](https://github.com/TakahiroNago/secureflow-ai/actions/runs/42470700770)。main のルールセットで全ジョブと GitGuardian を必須にしている | — | 充足 |
| 15 | README にセットアップ方法とアーキテクチャを記載する | README「セットアップ」「アーキテクチャ概要」「採用バージョン」「ヘルスチェック」「データベースロールとマイグレーション」「テストと静的解析」「CI」 | — | — | 隔離クローンは README の手順で作成した（2026-11-05）。採用バージョンの表は 2026-11-08 に lock ファイルと compose の値と照合した | 充足 |

## 4. 判定に含めないもの

- **公開環境への移行の前提条件**（[security-design.md §22](security-design.md)）：HTTPS、信頼できるリバースプロキシと接続元 IP、DB の無応答によるワーカーの枯渇への対策、ログの基盤とアラート、OpenAI のデータ保持と検出率の再評価など。満たすまで公開環境では起動しない。
- **受容した残存リスク**（[threat-model.md §7](threat-model.md)）：検出できない攻撃と個人情報（R-01、R-02、R-07）、評価専用データでの検出率 3.6%（R-31）、実モデルの挙動の変化（R-26）など。
- **MVP で実装しない機能**（[requirements.md §11](requirements.md)、[development-roadmap.md §7](development-roadmap.md)）。
