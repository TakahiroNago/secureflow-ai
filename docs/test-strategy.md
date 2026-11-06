# SecureFlow AI — テスト戦略

- 版：v1.9（2026-11-06）
- 状態：確定（v1.9：工程1-7 のダッシュボードのテストを追加。v1.8：工程1-6 の分析とワークフロー API のテストを追加。v1.7：工程1-5 のワークフロー基盤のテストを追加。v1.6：AUDIT-LOAD-01 の測定結果を追加。v1.5：工程1-4 の AI 基盤のテストを追加。v1.4：工程1-3 の監査ログテストを追加。v1.3：工程1-2 の認証テストを追加。v1.2：工程1-1 の設計レビューと検査の修正を反映。v1.1：Q-D13・Q-PII・D11・Phase 0 追加条件を反映）

---

## 1. 方針

1. テストは実装と同時に作成する。
2. AI API が利用できなくてもすべてのテストが実行できる（MockAiProvider）。CI で実キーは使わない。
3. セキュリティテストは通常のユニットテストと分離し、攻撃シナリオとして管理する（Pest group `security`）。
4. 検出エンジンのテストは「検出できること」と同時に「誤検知が少ないこと」も測る。**検出率100%を安全性の保証とみなさない。**
5. テストデータに実在の個人情報・実キーを使わない（`example.com`、テスト用カード番号、ダミーキー形式）。

## 2. テストレベルとツール

| レベル | ツール | 配置 | 内容 |
|---|---|---|---|
| バックエンド Unit | Pest | `backend/tests/Unit` | 検出器、Masker、Normalizer、OutputValidator、PlanHasher、StateMachine、ActionCatalog |
| バックエンド Feature（API） | Pest | `backend/tests/Feature` | エンドポイント、認証・認可、バリデーション、エラー形式 |
| セキュリティ | Pest（group: security） | `backend/tests/Security`（工程1-1で `Pest.php` と `phpunit.xml` に登録） | 攻撃シナリオ（§5） |
| データ分離 | Pest（group: isolation） | `backend/tests/Isolation` | 2組織×3ロールの総当たり |
| 並行性 | Pest（2つのDB接続） | `backend/tests/Concurrency` | 行ロック・一意制約・二重実行 |
| フロントエンド | Vitest + Testing Library | `frontend/src/**/*.test.tsx` | コンポーネント、入力検証、エラー表示、画面遷移、テキスト描画 |
| E2E | Playwright | `e2e/` | 主要シナリオ、XSS、承認フロー |
| 静的解析 | Larastan, ESLint, tsc, Pint | CI | 型・規約・危険API |
| SAST / SCA | Semgrep, Trivy, composer audit, npm audit | CI | 脆弱パターン、依存関係、シークレット |
| アプリ内自己診断 | SecuritySelfTestRunner | アプリ | 稼働中の検出エンジン・ポリシーの検証（§6） |

## 3. カバレッジ目標

| 対象 | 行カバレッジ |
|---|---|
| `app/Security`、`app/Domain` | 90%以上 |
| バックエンド全体 | 80%以上 |
| フロントエンド | 70%以上 |

カバレッジは目安であり、§5 のケースがすべて存在し成功することを優先する。

## 4. モックAIのシナリオ

MockAiProvider はテスト設定（コンストラクタ引数）でのみ応答を切り替える。入力中のマーカーでは切り替えない（本番では mock は無効）。

| シナリオ | 応答 | 検証対象 |
|---|---|---|
| `normal` | 正しいタスクJSON | 正常系 |
| `malformed_json` | 壊れたJSON | スキーマ検証 |
| `extra_keys` | 未知キー付きJSON | 未知キー拒否 |
| `oversized` | 長さ上限超過 | 長さ検証 |
| `script_tag` | `<script>`、`onerror=` を含む文字列 | 無害化・テキスト描画 |
| `forbidden_action` | `email.send`、`shell.exec` | forbidden判定 |
| `unknown_action` | 未定義 action_type | スキーマ違反 |
| `permission_inflation` | 過大な requested_permissions | 権限照合 |
| `secret_leak` | 出力にAPIキー形式 | 出力マスキング |
| `canary_leak` | カナリア文字列を含む | Critical 判定 |
| `timeout` / `rate_limited` / `server_error` | 例外 | 再試行・エラー処理 |

## 5. セキュリティテストケース

要件4.9の12ケース（ST-01〜12）と追加ケース。

| ID | テスト | 期待結果 | CI | 自己診断 |
|---|---|---|---|---|
| ST-01 | 通常の業務依頼 | 正常にタスク生成 | ○ | ○ |
| ST-02 | プロンプトインジェクション（日英・各カテゴリ） | 検知・警告。High/Critical は AI 未呼び出し | ○ | ○ |
| ST-03 | APIキー形式の文字列 | 検出（severity critical / action block）、**処理停止**（422 `INPUT_BLOCKED`、AI未呼び出し、本文・抜粋を保存しない） | ○ | ○ |
| ST-04 | メールアドレス（および電話番号・カード番号・マイナンバー形式） | 検出・`[EMAIL_REDACTED]` 等に置換し（action mask_continue）、マスク済みテキストで処理続行。AI送信内容に原文が含まれない | ○ | ○ |
| ST-05 | 未認証APIアクセス | 401（全保護ルート） | ○ | — |
| ST-06 | 権限のない操作（member・auditor が承認・却下、member が監査ログ参照、admin 以外の設定変更、auditor の状態変更） | 403 | ○ | ○（Policy直接） |
| ST-07 | 不正JSON（リクエスト／AI出力） | 422 ／ 分析失敗 | ○ | ○（AI出力） |
| ST-08 | 未承認タスクの実行 | 409 拒否 | ○ | ○ |
| ST-09 | 承認後の内容変更 | Draft に戻り再承認要求、旧承認で実行不可 | ○ | ○ |
| ST-10 | HTMLスクリプトの出力 | 無害化、画面でテキスト表示 | ○＋E2E | ○ |
| ST-11 | 大量リクエスト | 429 | ○ | — |
| ST-12 | 他ユーザーのデータ参照 | 404 | ○ | ○（Policy直接） |
| ST-13 | 難読化インジェクション（ゼロ幅文字・全角・Base64） | 正規化後に検知、レベル+1 | ○ | ○ |
| ST-14 | 間接インジェクション（役割マーカー入り貼付文書） | High 検知 | ○ | ○ |
| ST-15 | システムプロンプト抽出・カナリア漏洩 | IJ-EXF 検知／カナリアで Critical | ○ | ○ |
| ST-16 | 禁止操作を含むワークフローの提出 | 409 `FORBIDDEN_ACTION_PRESENT` | ○ | ○ |
| ST-17 | 編集で action_type を禁止操作に変更 | forbidden 判定、提出不可 | ○ | ○ |
| ST-18 | AI申告権限の水増し | 導出権限のみ採用、mismatch finding | ○ | ○ |
| ST-19 | AI出力中の機密情報 | 個人情報はマスキングして保存、認証・秘密情報は分析を blocked（結果を保存しない） | ○ | ○ |
| ST-20 | 古い plan_hash での承認 | 409 `PLAN_HASH_MISMATCH` | ○ | ○ |
| ST-21 | 自己承認（admin が自分の作成したワークフローを承認：アプリ経由・DB直接INSERT） | 403 `SELF_APPROVAL_FORBIDDEN`／DBトリガーで拒否 | ○ | ○ |
| ST-22 | 二重実行（同時2リクエスト・同一キー再送・別キー再送） | 実行は1件のみ | ○ | ○ |
| ST-23 | 別組織データへのアクセス（全エンドポイント） | 404、データ漏洩なし | ○ | — |
| ST-24 | ログイン5回失敗 | ロック、同一エラーメッセージ | ○ | — |
| ST-25 | ログイン前後のセッションID | 再生成されている | ○ | — |
| ST-26 | CSRFトークンなしの状態変更 | 419 拒否 | ○ | — |
| ST-27 | 存在する/しないメールでのログイン失敗 | 応答同一 | ○ | — |
| ST-28 | 監査ログの UPDATE/DELETE/TRUNCATE、行の改ざん | DB拒否／チェーン検証で検出 | ○ | ○（検証のみ） |
| ST-29 | 例外発生時のレスポンス・ログ | 内部情報・秘密情報なし | ○ | — |
| ST-30 | AI利用上限超過 | 429、AI未呼び出し | ○ | ○ |
| ST-31 | AIリクエストに tools パラメータがない／送信先が固定 | HTTPフェイクで検証 | ○ | — |
| ST-32 | SQLインジェクション文字列を各入力に投入 | 正常にエスケープ、エラーなし | ○ | — |
| ST-33 | 実行中のワーカー停止を模擬 | 停滞回収で Failed、再承認必須 | ○ | — |
| ST-34 | 全ルートの認証・Policy 設定 | 認可漏れルートなし（ルート一覧から自動検査） | ○ | — |
| ST-35 | 認証・秘密情報の各形式（トークン・パスワード・PEM秘密鍵・OpenSSH鍵）を入力・編集・AI出力に含める | 入力・編集は 422 `INPUT_BLOCKED`、AI出力は analysis blocked。いずれも本文を保存しない。severity と action が別フィールドで返る | ○ | ○ |
| ST-36 | マスキング失敗の模擬（検出器の例外・タイムアウト、再検査で残存、不正UTF-8） | fail closed：`MASK-FAIL` で停止、AI未呼び出し、`masking_status=failed` かつ `decision=block` | ○ | ○ |
| ST-37 | 承認可能な admin がいない組織（admin が作成者1名のみ／admin 不在） | 承認できず、実行APIは 409 `APPROVAL_NOT_VALID`。`approver_available=false` が返る | ○ | ○ |
| ST-38 | auditor・member による承認のDB直接INSERT | DBトリガー `approvals_require_admin` で拒否 | ○ | ○ |
| ST-39 | 検出限界の注意文言 | 入力検査・分析・ワークフロー詳細・承認コンテキストのレスポンスに `limitations_notice` が常に含まれる（検出0件でも） | ○ | — |

## 6. アプリ内セキュリティ自己診断（D6）

- 管理者が画面から実行。`RunSecuritySelfTestJob` でキュー実行。
- **MockAiProvider を強制使用**（実AIを呼ばない・コストなし）。
- HTTP を自分自身に送らず、サービス層・Policy・検出エンジンを直接呼び出す（SSRF・副作用を避ける）。
- 各ケースは DB トランザクション内で実行しロールバック。結果は別トランザクションで `security_test_results` に保存。
- 対象：「自己診断」列が ○ のケース。HTTPレベルのケース（401、CSRF、レート制限等）は CI のセキュリティテストで検証し、自己診断画面にはその旨を表示する。
- 結果には実行時の `ruleset_version`・`policy_version` を記録し、ダッシュボードとセキュリティ管理画面に最新結果を表示する。

## 7. 検出エンジンのコーパス評価

- `backend/resources/security/corpus/` に攻撃コーパス（インジェクション日英・難読化・間接）と正常業務文コーパスを置く。
- 指標と初期目標：

| 指標 | 初期目標 |
|---|---|
| 形式が定義された機密情報（メール・カード・キー等）の検出率 | コーパス上100% |
| 認証・秘密情報コーパスの `block` 判定率 | コーパス上100% |
| 正常業務文コーパスでの誤停止率（`block` 判定） | 1%以下 |
| インジェクションコーパスの Medium 以上検出率 | 90%以上 |
| 正常業務文コーパスの誤検知率（Medium以上） | 5%以下 |

- 目標値はコーパス上の値であり、未知の攻撃に対する性能を保証しない。結果を CI のレポートに出力する。

## 8. 並行性テスト

- 2つの DB 接続を使い、一方が行ロックを保持した状態で他方の承認・編集・実行が待機または 409 になることを検証。
- 一意制約（approval_id、workflow_revision_id、idempotency_key、部分一意インデックス）に直接重複INSERTして拒否されることを検証。
- E2E で同時に2回の実行要求を送り、実行が1件であることを検証。

## 9. フロントエンドテスト

- `<script>`・`<img onerror>` を含むAI出力を描画し、DOM に要素が生成されずテキストとして表示されること。
- 個人情報検出の限界文言が入力画面・検査結果・承認画面に表示されること。
- APIエラー（401→ログイン画面遷移、403、409ハッシュ不一致→再読込案内、422、429）の表示。
- 承認画面：自分が作成者の場合に承認ボタンが無効、Medium 以上でリスク確認チェックなしに承認できないこと（サーバー側でも検証）。auditor・member には承認ボタンが表示されないこと。`approver_available=false` の場合に案内文が表示されること。
- 入力検査の表示：`severity` と `action` を別々に表示し、`block` の場合は停止理由と該当位置が表示されること。

## 10. E2E シナリオ（要件9）

1. member がログイン → 2. 業務内容を入力 → 3. スキャンプレビューと限界文言を確認 → 4. AI（モック）がタスク生成 → 5. 検査結果を確認 → 6. 提出 → 7. member は承認できないことを確認 → 8. admin がログインし承認 → 9. member が実行 → 10. 模擬実行が完了し結果が保存 → 11. admin/auditor が監査ログで一連の履歴を確認。
追加：承認後編集で再承認要求、XSS出力のテキスト表示、自己診断の実行と結果表示。

## 11. CI（GitHub Actions）

| ジョブ | 内容 |
|---|---|
| secret-scan | gitleaks（Git 履歴全体）、Trivy（fs の secret スキャン）。**Phase 0 から実施** |
| backend | Pint（--test）、Larastan、Pest（Unit/Feature/Isolation/Concurrency）※PostgreSQL・Redis サービスコンテナ。スキーマ作成は owner、テスト実行は app ロール |
| security | Pest group security、コーパス評価レポート |
| frontend | ESLint、tsc --noEmit、Vitest、ビルド |
| e2e | Docker Compose 起動 → Playwright |
| sast-sca | Semgrep、Trivy（fs・イメージ・secret）、composer audit、npm audit |

Phase 0 では secret-scan と backend / frontend の Lint・型・テスト・ビルドを実施する。security・e2e・sast-sca は Phase 3 で追加する。

## 12. Phase 0 基盤テスト

| ID | テスト | 期待結果 | 実施方法 |
|---|---|---|---|
| P0-HC-01 | Liveness `GET /api/health/live` | 200 `{"status":"ok"}`。DB・Redis 停止中でも 200。余計なキー・バージョン情報を含まない | Pest、curl |
| P0-HC-02 | Readiness `GET /api/health/ready` | DB・Redis 到達時 200 `{"status":"ok"}`、いずれか不可で 503 `{"status":"unavailable"}`。失敗した依存名・エラー詳細を含まない | Pest（接続先を不正値にして検証）、curl |
| P0-HC-03 | `app` コンテナの healthcheck | `artisan` と `public/index.php` の存在、php-fpm の TCP 応答、`artisan --version` の成功をすべて確認する。空の bind mount で unhealthy になる。DB・Redis には接続しない | `test-app-healthcheck.sh`（負のテスト） |
| P0-HC-04 | `worker` / `scheduler` コンテナの healthcheck | Laravel ソースの存在、`artisan --version` の成功、`queue:work` / `schedule:work` の実プロセス（PID 1）を確認する。処理するジョブがないだけでは unhealthy にならない | `test-worker-healthcheck.sh`（負のテスト） |
| P0-DB-01 | app ロールで DDL（`CREATE TABLE`） | 権限エラーで失敗 | Pest（app 接続） |
| P0-DB-02 | owner ロールでのマイグレーション経路 | `migrate` サービスで `migrate` が成功。`app` / `worker` / `scheduler` には `DB_MIGRATOR_*` が存在しない。`app` での `migrate` は権限エラーで失敗する | `docker compose run --rm migrate`、`verify-infra.sh` |
| P0-DB-03 | ロール属性 | 4ロールとも NOSUPERUSER / NOCREATEDB / NOCREATEROLE。PUBLIC に public スキーマの CREATE 権限なし | psql での確認SQL |
| P0-DB-04 | 開発用とテスト用のロールの分離 | テスト用の2ロールは開発用DB・`postgres` に接続できない。開発用の2ロールはテスト用DBに接続できず、テスト用DB内の権限も持たない。テスト用 app はテスト用 owner のメンバーではない。`test` / `migrate` は各自のロールの認証情報のみを受け取る | `verify-infra.sh` |
| P0-NET-01 | ポート公開 | `docker inspect` の設定値と実際のバインドが許可リスト（nginx・frontend のみ）と一致し、公開先は 127.0.0.1 のみ。`0.0.0.0`、IPv6（`::`）、アドレスなし、想定外のポート、host ネットワーク、publish-all を失敗にする。評価できない場合も失敗にする | `check-published-ports.sh`、`test-published-ports.sh`（負のテスト） |
| P0-NET-02 | Redis 認証 | パスワードなし接続が `NOAUTH` で拒否される | `redis-cli` |
| P0-SEC-01 | リポジトリの秘密情報 | gitleaks・Trivy secret で検出0件。`.env` が追跡対象外 | CI、`git check-ignore` |
| P0-FE-01 | フロントエンドのスモーク | 画面表示、Vite proxy 経由で live ヘルスチェック取得、`dangerouslySetInnerHTML` の使用で ESLint がエラー | Vitest、ESLint |

テスト用データベースは `secureflow_test`（開発用DBとは別）とする。

## 13. 工程1-1 のDBテスト

テスト本体は `secureflow_test_app` ロールで実行する。`secureflow_test_owner` の接続はスキーマの初期化とマイグレーションに限定する（[database-design.md §4.6](database-design.md)）。

| ID | テスト | 期待結果 |
|---|---|---|
| DB-MIG-01 | マイグレーション | up → rollback → 再 up が成功し、rollback 後にテーブルと関数が残らない |
| DB-PRIV-01 | テーブル権限 | 4テーブルの権限が [database-design.md §4.2](database-design.md) と過不足なく一致する。app から `migrations` にアクセスできない |
| DB-PRIV-02 | `audit_logs` の INSERT（工程1-3で変更） | app の直接の INSERT はすべて拒否される（工程1-1では `id` を除く列を許可していた）。`nextval()` と、任意の `id` を指定した INSERT（`OVERRIDING SYSTEM VALUE` を含む）も拒否される |
| DB-ROLE-01 | ロール | テスト本体はテスト用 app、DDL はテスト用 owner で実行される。どちらも開発用DB・`postgres` に接続できない。テスト用 owner は DB・ロールを作成・削除できない。テスト用 app はテスト用 owner に切り替えられない。`secureflow_app` はテスト用DB内の権限を持たない。`migrate` 系コマンドの後も既定の接続がテスト用 app のまま |
| ST-28（DB部分） | `audit_logs` の改変 | app の UPDATE / DELETE / TRUNCATE は権限エラー。owner でも、行がある状態の UPDATE / DELETE / TRUNCATE はトリガーで拒否される |
| DB-CON-01 | 制約 | NOT NULL の列挙列への NULL、不正な列挙値、大文字小文字違いのメール重複、範囲外の設定値が拒否される。ID を省略した生SQLの INSERT が拒否される |
| DB-GUARD-01 | テスト用DBのガード | [database-design.md §4.6](database-design.md) の各条件について、1つでも満たさない場合に中断する |
| DB-GUARD-02 | 破壊的コマンドの制限 | `APP_ENV=testing` を指定した場合を含め、テスト用DB以外では `migrate:fresh`・`migrate:refresh`・`migrate:reset`・`db:wipe` が拒否され、データが残る。開発用DBの `migrate:rollback --step` は実行できる。本番相当では `migrate:rollback`・`key:generate`・`queue:clear`・`queue:flush`・`db:seed`・`schema:dump` が拒否され、`cache:clear` は拒否されない |

## 14. 工程1-2 の認証テスト

§5 の ST-05、ST-24〜27 に加えて、以下を確認する。

| ID | テスト | 期待結果 |
|---|---|---|
| AUTH-ERR-01 | ログイン失敗の応答 | 存在しないメールアドレス、パスワード不一致、`is_active=false`、ロック中で、ステータス・`code`・`detail` が同一の 401 `AUTH_FAILED`。すべての場合でハッシュ検証が実行される |
| AUTH-LOCK-01 | ロック | 連続5回の失敗でロックされ、正しいパスワードでも 401。15分後に解除。並行した失敗でも回数を取りこぼさない。成功で回数がリセットされる |
| AUTH-LOCK-02 | ロックと既存セッション（T-33） | ロック中も既存セッションは有効なまま（工程1-2） |
| AUTH-LOCK-03 | ロックと承認・実行（T-33） | ロック中の admin は承認でき、ロック中の所有者は実行できる。`is_active=false` では拒否される。承認可能な admin の判定にロック中の admin を含める（API が実装される工程2-5・2-6で実施） |
| AUTH-RATE-01 | レート制限 | 6回目は 429 と `Retry-After`。`X-Forwarded-For` の詐称で回避できない |
| AUTH-SES-01 | 無効化 | `is_active=false` にすると、既存セッションの次のリクエストが 401 になり、セッションが破棄される |
| AUTH-SES-02 | セッションの期限 | 無操作30分で失効。操作を続けても絶対12時間で失効 |
| AUTH-SES-03 | ログアウト | セッションが破棄され、同じ Cookie では 401。CSRF トークンが再生成される |
| AUTH-CSRF-01 | ステートフルドメイン | 許可された `ホスト:ポート` からのみ Cookie 認証が有効。許可外のオリジンでは認証されない |
| AUTH-PW-01 | パスワード変更 | 他のセッションは無効になり、現在のセッションは有効なまま。`password_changed_at` が更新される |
| AUTH-PW-02 | パスワード変更の拒否 | 現在のパスワード不一致は 422 `CURRENT_PASSWORD_INVALID` で、ロックの失敗回数に数えない。12文字未満、上限超過、辞書に一致（大文字小文字を問わない）、現在と同じは 422 |
| AUTH-PW-03 | 辞書の完全性 | 同梱ファイルの SHA-256 が [security-design.md §12.1](security-design.md) と一致する。実行時に外部へ通信しない |
| AUTH-HASH-01 | ハッシュ | 保存値が Argon2id。応答・ログにパスワードとハッシュが含まれない |
| AUTH-CMD-01 | `user:create` | パスワードは対話入力のみ（引数なし）。ポリシー違反を拒否。出力にパスワードを含まない |
| AUTH-SEED-01 | Seeder | 実行後もログイン可能なユーザーが増えない。投入されるのは組織や初期設定のみ |
| AUTH-E2E-01 | 実際の HTTP での通し確認（`scripts/test-auth-flow.sh`） | nginx と Vite proxy を経由し、Redis のセッション、CSRF、Argon2id、ロック、レート制限、ログへの非出力を確認する。ユーザーを作成するため、既定のプロジェクトでは実行を拒否し、使い捨ての環境と CI でのみ実行する |

## 15. 工程1-3 の監査ログテスト

§5 の ST-28 と、§13 の DB-PRIV-02 の変更に加えて、以下を確認する。テスト本体は `secureflow_test_app` で実行する。改ざんを再現する場合のみ `secureflow_test_owner` でトリガーを一時的に無効化する（テスト用DBに限る）。

| ID | テスト | 期待結果 |
|---|---|---|
| AUDIT-MIG-01 | マイグレーション | up → rollback → 再 up が成功する。`audit_logs` に行があると up・down とも中断する。`audit_logs_id_seq` の値を変更しない |
| AUDIT-PRIV-01 | 権限（T-34） | app は `audit_logs`・`audit_chain_heads` に SELECT のみ。直接の INSERT・UPDATE・DELETE・TRUNCATE は拒否される。app に `audit_append()` の EXECUTE があり、補助関数の EXECUTE はない。`PUBLIC` に EXECUTE がない。関数の所有者がマイグレーションのロールで、app はそのメンバーでない |
| AUDIT-FN-01 | 関数の属性と引数（T-34） | `audit_append()` に定数として書かれた `event_id` の制約名がカタログの実際の名前と一致する。通常の追記の経路に例外ブロックを通らない。[database-design.md §3.12.4](database-design.md) の確認方法に従い、カタログで所有者、SECURITY DEFINER（`audit_append()` のみ）、`search_path = pg_catalog, pg_temp`、`lock_timeout` を確認する。`audit_append()` と補助関数の本文に `EXECUTE` 文と `format(` がなく、テーブル参照がスキーマ修飾されている。一時スキーマに同名のテーブルや関数を作っても呼び出されない。不正な引数（NIL UUID、存在しない組織、他組織の actor、actor の組み合わせ、不正な列挙値、マスク付きの IP、不正な metadata）を拒否し、エラーメッセージに値を含まない |
| AUDIT-META-01 | metadata の形式 | 入れ子、配列、`null`、小数、`1.0`、範囲外の整数、不正なキー、キー数・バイト数の超過、制御文字を拒否する |
| AUDIT-HASH-01 | 固定テストベクトル | `backend/tests/Fixtures/audit-hash-vectors.json`（[database-design.md §3.12.3](database-design.md)）の値を、PHP の実装と PostgreSQL の補助関数の両方が再現する。NULL・空文字・`-` のハッシュがすべて異なる。Unicode の NFC と NFD のハッシュが異なる（正規化しない）。長さがバイト数である（2文字・6バイト、1文字・4バイト）。時刻はセッションの `TimeZone` と入力のオフセットに関わらず UTC・マイクロ秒6桁になる。JSONB は重複キー・キーの順序・エスケープ・U+2028・`{}` を正規形にする。**一致しない場合は値を書き換えず報告する** |
| AUDIT-CHAIN-01 | チェーンの構造 | 組織ごと、システムの各チェーンが1から連番で、`prev_hash` が前の行の `hash` と一致する。ROLLBACK した記録の番号が欠番にならない。`id` の順序と `chain_seq` の順序が異なっても検証に影響しない |
| AUDIT-CONC-01 | 並行書き込み | 複数の接続から同じチェーンに同時に記録しても、欠番・重複がなく検証が成功する。別のチェーンが待たされない。ロック待ちが2秒を超えると `55P03` で失敗する。検証中も記録が止まらず、誤検出がない |
| AUDIT-VERIFY-01 | 改ざんの検出（ST-28） | 値・metadata・時刻・event_id の変更、途中の行の削除、末尾の行の削除、チェーン間の行の移動、ヘッドの変更、ヘッドの削除、`ip_address` のマスク長の変更を、それぞれ [database-design.md §3.12.5](database-design.md) の理由コードで検出する。他のチェーンは成功のまま |
| AUDIT-VERIFY-02 | 検出の限界の明示 | 末尾の削除＋ヘッドの巻き戻し、チェーン全体の再計算は `--anchor` なしでは検出されず、改ざん前に保管した `audit:head` の値を `--anchor` に渡すと `ANCHOR_MISMATCH` で検出される（検出できないことを仕様として固定する） |
| AUDIT-CMD-01 | コマンド | `audit:verify` の終了コードが 成功 0 / 検証失敗 1 / 実行不能 2。`--all` でチェーンが1つもない場合は 0 で、検証していないことを出力する。行とヘッドが丸ごと消されたチェーンは、`--all --anchor` で `ANCHOR_MISMATCH` となる（チェーンが1つも残らない場合を含む）。`audit:head` の出力形式が固定されている。出力に行の内容・秘密情報を含まない |
| AUDIT-VFAIL-01 | 検証失敗時の動作 | 自動修復しない（行とヘッドが変わらない）。サービスを止めない（その後の記録とログインが成功する）。重大ログを出力し、`audit.verification_failed` を1件だけ記録する。記録に失敗しても終了コードは 1 のままで、再帰しない |
| AUDIT-EVENT-01 | 認証イベントの記録 | 成功・失敗・ログアウト・ロック・パスワード変更で、[security-design.md §16.5](security-design.md) のチェーン・actor・resource・metadata が記録される |
| AUDIT-FAIL-01 | 記録の失敗（T-37）。事前確認の成功後に記録が失敗する場合 | `auth.login`：503 で、セッションが開始されず、`last_login_at` と失敗回数が変わらない。`auth.login_failed`：503 で、失敗回数が維持される。`auth.locked`：503 で、ロックが維持される。`auth.password_changed`：503 で、パスワード、`password_changed_at`、他のセッションが変わらない。`auth.password_change_failed`：503。`auth.logout`：204 でセッションが破棄される。いずれも重大ログを出力し、`outcome` と `failure_class` で区別できる。別トランザクションのイベントは、記録が失敗しても業務処理（失敗回数・ロック・セッションの破棄）のコミットが残る。**実際のエラー（別の接続でヘッドをロックした `55P03`）を少なくとも1件、実トランザクションで確認する** |
| AUDIT-AVAIL-01 | 事前確認（T-39、T-35） | DB unavailable と Audit unavailable の事前確認の失敗時に、未知のメールアドレス、不一致、無効、ロック中、正しい認証情報のすべてが同一の 503 で、ユーザーの検索とハッシュの検証が実行されない。パスワード変更も現在のパスワードの正否に関わらず同一の 503。`Hash::check` が事前確認の失敗時に呼ばれない。事前確認が行を追加しない。フラグが立っている間は DB に接続せず（認証済み API を含む。ログインのない要求は 401 のまま）、`Retry-After` が固定値（`DB_UNAVAILABLE_TTL_SECONDS`、コンテナでの実効値は既定の30秒。フラグの残り時間ではない）で、503 でフラグが延長されない。TTL の経過後の再確認は1要求のみが行い、同時の他の要求は待たずに 503 となる。TTL の経過後に事前確認が**実際に DB へ接続して**再実行され、回復していれば通常に戻り、回復していなければ再びフラグが立つ（DB を実際に停止・再開して、使い捨ての環境で確認する）。フラグの設定に失敗しても応答が変わらず、重大ログが出力される。監査を迂回する経路がない |
| AUDIT-STATE-01 | 3つの状態の分離（T-35、T-39） | [security-design.md §16.5.1](security-design.md) の分類のとおり。`53100` と `42501`・`42883`・`42P01`・`25006` の `audit_append()` の失敗で直ちに Audit unavailable となり、DB unavailable にならない。**`55P03`・`57014`・`22023`・未分類のコードは、何回連続しても全体の状態にならず**、その要求のみ 503 となる。ログの `failure_class` が `storage`、`permanent_config`、`transient`、`connection`、`unclassified` で区別される。他のクエリのエラーでは変化しない。Audit unavailable の間、認証済みの読み取り API は通常どおり。readiness は `permanent_config` で 200、`storage_scope=db_suspected` で 503。監査必須の成功操作は業務処理もコミットしない |
| AUDIT-ORACLE-01 | 監査の失敗時の応答からの判別（T-39） | **監査の追記を失敗させ、正しいパスワード、誤ったパスワード、無効、ロック中で、応答のステータス、`code`、`type`、`title`、`detail`、`Content-Type`、`Retry-After` が `trace_id` 以外すべて同じ 503 であることを比較する。** パスワード変更も、現在のパスワードの正否とコミットの前後で同じ 503 になる。`failure_class` のすべてについて行う。正しいパスワードでセッションが開始されない。誤ったパスワードで失敗回数とロックが維持される。`AUTH_FAILED` と `CURRENT_PASSWORD_INVALID` が返らない |
| AUDIT-RECOVER-01 | 回復の確認（使い捨てのDBで行う） | `outage_id` ごとに `audit.availability_checked` が最大1件で、`metadata.outage_id` を持つ。同時の要求で確認が1件のみ実行され、排他の期限切れで2つの要求が確認しても1件に収まる。業務トランザクションの外で実行され、業務のロールバックで消えない。**追記のコミットの確認の後にのみ状態が消える。** 追記の失敗で行が増えず、監査イベントが再帰的に発生しない。**DB 関数：** 同じ `event_id`・同じ `outage_id` のときのみ `SF001` を返し、ヘッドと行が変わらない。**次の場合は `SF001` にならず元の `23505` のまま：** `(chain_id, chain_seq)` の違反、別の制約、既存の行の `event_type` や `chain_id` や `metadata.outage_id` が異なる場合、他のイベント種別。**PHP：** `errorInfo[0]` の `SF001` を判定し、`getCode()` とメッセージを使わない。**`SF001` でも、状態の `outage_id` の不一致、再読み取りの行の不一致では回復済みとならず**、`metric=audit.recovery_check_conflict` が出力される。`23505` は記録済みと判断されない。回復の確認以外の経路の `SF001` を成功として扱わない。**Redis の消失：** 状態が消えた後の次の失敗で新しい `outage_id` が発行され、同じ物理的な障害でも別の行が記録されうることを確認する |
| AUDIT-STORAGE-01 | `53100` の扱い（固定データと注入で確認。実際の枯渇は実装前の検証項目） | `audit_append()` の `53100` で Audit unavailable となり、`storage_scope=db_suspected` が出力される。**`audit_only` と判定されない。** `storage_area` は文言から分類され、文言を変えても状態が変わらない。監査必須の操作は 503 で業務処理をコミットしない。他のクエリの `53100` は状態を変えず `metric=db.storage_error` を出力する。回復の確認の成功で `recovery_scope=audit_path` が出力され、DB 全体の回復と表明しない。**`db_suspected` の間、`/api/health/ready` は 503 `{"status":"unavailable"}`（内部情報なし）、`/api/health/live` は 200、回復の確認の後に readiness が 200 に戻る。** `permanent_config` では readiness が 200 のまま。**コンテナの healthcheck と再起動の定義が `/api/health/ready` を参照しないこと、healthcheck が readiness の 503 で unhealthy にならないことを `compose.yaml` の検査で確認する** |
| AUDIT-WAL-01 | WAL 領域の枯渇（`server_panic`） | `HY000`（`PANIC`）で `cause=server_panic` の候補となり、**確認プローブの `08006` で DB unavailable になる。** `53100` として扱わない。`storage_scope=db_suspected` にしない。プローブが成功すれば DB unavailable にならない。文字列を変えても状態の判定が変わらない。readiness は 503、liveness は 200。一時ファイルと監査テーブルの領域の枯渇と区別される | 固定データと注入。実環境：使い捨ての環境で WAL 領域を枯渇させる |
| AUDIT-MON-01 | `audit.unavailable` の監視 | `scheduler` が毎分ゲージを出力し、`value` が状態と一致する。Redis を読めなければ `unknown`。`audit:status` の終了コードが 0・1・2 になる。`permanent_config` の Audit unavailable の間、readiness は 200 のまま、ゲージは 1。ログに秘密情報を含まない |
| AUDIT-AUTHERR-01 | 認証の失敗と障害の区別 | [security-design.md §16.5.1](security-design.md) の応答の表のすべての行について、HTTP ステータス、`code`、監査ログ、サーバーログ、レート制限と失敗回数を確認する。**DB と Redis の例外が `AUTH_FAILED` にならない。** ユーザーの検索と失敗回数の更新の DB エラーは 503。その他の例外は RFC 9457 形式の 500 `INTERNAL_ERROR`。応答に内部情報を含まない |
| AUDIT-CODE-01 | DB unavailable の判定（T-35） | [security-design.md §16.5.1](security-design.md) のとおり、DB unavailable になるのは**確認プローブが `08006` で失敗した場合のみ**である。`HY000` と `08006` でプローブが実行され、`42601`、`42883`、`42501`、`25P02`、`25006`、`57014`、`55P03`、`22023`、`23505`、未知のコード、`PDOException` でない例外では実行されない。**プローブが成功すれば立たない（`pg_terminate_backend`、`idle_in_transaction_session_timeout`、`transaction_timeout`、瞬間的な接続の失敗）。** **`errorInfo[2]` の文字列を変更・削除しても判定と応答が変わらず、`cause` のみが変わる**（未知の文言は `unknown`）。`getCode()` と `causedByLostConnection()` を使わない。`rollBack()` の例外で最初の原因が失われない。頻度の制限が働く。**PostgreSQL・PHP・Laravel の更新時は、使い捨ての環境で実際の障害を起こして値を再確認する** |
| AUDIT-REDIS-01 | Redis の障害（T-40）。実際の Redis を使い捨ての環境で操作する | **停止**（コンテナの停止）、**接続失敗**（接続拒否、名前解決の失敗、認証エラー）、**接続タイムアウトと読み取りのタイムアウト**（無応答のサーバー）のそれぞれで：ログインとパスワード変更が RFC 9457 形式の 503 `SERVICE_UNAVAILABLE` と `Retry-After` を返す（既定の 500 にならない）。認証情報の正否、メールアドレスの有無で応答が `trace_id` 以外同一。`Hash::check` が実行されない。レート制限なしで認証が続行されない。別のストアに切り替わらない。§16.5.7 のログと `cause` が出力され、接続先・パスワードが出力されない。**認証済み API が同じ 503 を返す。`GET /api/health/live` は 200 のまま（フロントエンドの Origin 付きの要求を含む）。`GET /api/health/ready` は 503 `{"status":"unavailable"}` を返し、内部情報、接続文字列、例外メッセージを含まない。フロントエンド以外からの認証済み API は 401 のまま。Origin なしのログインは Redis の障害時に 503 で、**正常時の Origin と CSRF の検証の応答は変わらない。** セッションの保存が長時間待たない。**評価中に Redis が止まった場合も、応答が認証情報の正否に依存しない。**復旧後の動作**：追加の操作なしに次の要求から通常に戻る。`GET /api/health/ready` が 200 に戻る。レート制限が再び動作する（6回目が 429）。DB のロックが維持される。永続化なしの再起動で全セッションが失効する。長い接続を持つ `worker`・`scheduler` が再接続する |
| AUDIT-TX-01 | トランザクションの確認 | `recordInTransaction()` はトランザクション外で、`recordAfterTransaction()` はトランザクション内で例外になる。`recordAfterTransaction()` の実行中に接続が切れても、Laravel の自動再実行で `audit_append()` が2回実行されない。業務のロールバックで同じトランザクションの記録が消え、ヘッドも戻る。ロールバック後の失敗イベントは残る。1トランザクションで別のチェーンへの記録を拒否する |
| AUDIT-ACTOR-01 | actor の決定 | `AuditLogger` の公開 API が actor の ID を受け取らない。`audit_append()` を呼ぶのが `AuditWriter` のみであり、`AuditWriter` を使うのが `AuditLogger` と、actor を持たないシステムイベントの `AuditAvailability`・`audit:housekeeping` のみである（Pest の arch テスト）。リクエストの入力で actor・組織を変えられない |
| AUDIT-SYS-01 | システムチェーンの分離（T-36） | NIL UUID の組織を作成できない。未知のメールアドレスの失敗はシステムチェーンに記録される。組織スコープのクエリにシステムチェーンの行が含まれない（API の確認は工程2-7） |
| AUDIT-SYS-02 | 匿名イベントの抑制（T-35） | 環境変数で上限を変更できる。IP 単位のレート制限で 429。全体上限を超えると記録されず、応答は変わらず、最初の超過で直ちに重大ログが出力される。期間の終了後に件数の重大ログが**チェーンへの記録より先に**出力され、`audit.events_suppressed` が正しい件数で1件記録され、`audit:verify` に件数が表示され、検証は成功のまま。**チェーンへの記録が失敗しても重大ログで発生と件数が分かり、次回の実行で再度記録される。** 組織チェーンの記録は影響を受けない |
| AUDIT-PWCHG-01 | パスワード変更と Redis の障害（T-41） | 下記の「パスワード変更の障害テスト」のすべてが成立する |
| AUDIT-DBTO-01 | DB のタイムアウト（T-42）。実際の障害を使い捨ての環境で起こす | 接続時の無応答で `08006`、文の超過で `57014`、ロック待ちで `55P03`（`statement_timeout` より短いこと）、アイドルのトランザクションで切断されヘッドのロックが解放され、プローブが成功してフラグが立たない、応答待ちのネットワーク断で keepalive により検出、送信時のネットワーク断で `tcp_user_timeout` により検出。**keepalive と `tcp_user_timeout` が、Laravel のコネクタの拡張を含めて対象の実際の接続に適用されていることを、挙動で確認する**（設定値の存在では合格としない）。[security-design.md §16.5.6](security-design.md) の表のとおり、各イベントの業務トランザクションと応答が動作する。値を環境変数で変更できる。`audit:verify` がタイムアウトの影響を受けない |
| AUDIT-LOGAGG-01 | 障害中のログの集約（T-43） | 複数のプロセスからの連続した失敗で、`started` が1件、`continuing` が間隔ごとに1件、`recovered` が1件となる。**件数は概数である**（[security-design.md §16.5.7](security-design.md)）：要求が1つずつであれば要求数と一致する。並行の要求では、ロックを取得できなかった要求は数えられず、**件数は要求数を超えない。** 要求数との一致を合格の条件にしない。原因の変更で `continuing` が出力される。短時間の繰り返しで `flap_count` に集約される。状態は Redis に依存しない（Redis の停止中に動作する）。状態ファイルが書けない、権限がないと `aggregation=degraded` になり、応答は変わらない。ロックの保持中にプロセスを終了しても次のプロセスが止まらない。破損した状態ファイルは破棄され `state_reset=true` が付く。書き込みの中断で内容が壊れない。別のコンテナと状態を共有しないこと、再作成で `started` が再度出力されることを確認する。`RedisException` が要求ごとに別途出力されない。readiness の失敗は依存先ごとに集約され、Redis の障害を `storage` と二重に数えない |
| AUDIT-LOAD-01 | 負荷試験（暫定値の確認） | 下記の項目を使い捨ての環境で測定し、結果を記録する。値が環境に依存するため CI の合否にしない |
| AUDIT-SEC-01 | 秘密情報（T-38） | パスワード、パスワードハッシュ、メール欄に入力された文字列、未知のメールアドレス、セッションID、ハッシュが、監査ログと重大ログのどちらにも含まれない。`auth.password_changed` の `metadata` が `{}` である。パスワードの更新のトランザクションが DB エラーで失敗しても、ログにパスワードの平文とハッシュ値が出ない。DB エラーを起こしてもログにバインド値が出ない。未許可の metadata キーが破棄される |
| AUDIT-TIME-01 | 処理時間（T-19、T-39、R-14） | 既知・未知のメールアドレスのログイン失敗、正しい・誤った認証情報、**片方のチェーンのみが失敗またはロック待ちの状況**の処理時間を、使い捨ての環境で実測して記録する。値が変動するため CI の合否にしない。有意な差があればレビューで対処を判断する。**測定の結果にかかわらず、R-14 を解消済みとしない** |
| AUDIT-SESSION-01 | パスワード変更後のセッション（`scripts/test-session-invalidation.sh`、Pest） | 変更後に実際の認証済み API を呼び出して確認する。①変更を実行したセッションは維持される。②変更前から存在した他のセッションは 401 になる（同じキー・同じ内容の再試行を最初の要求とした場合、同時に送った場合を含む）。③再ログイン後の新しいセッションは、同じキー・同じ内容の再試行で 200 となり、再実行されない。④**同じセッションからの並行要求（`scripts/test-password-concurrency.sh`）で、200 と新しいセッションの Cookie が各1件のみ、有効なセッションIDが1つのみ、Redis に保存されたセッションが増えない。古いIDの要求が削除済みのセッションを書き戻さず、Cookie を返さない** |
| AUDIT-SESSION-02 | 並行する要求とセッションの終了（`scripts/test-session-race.sh`、Pest。使い捨ての環境） | セッションを読み込み、保存する前の要求を止めた状態で、ログイン済みの `GET` とログアウト、ログイン済みの `GET` とパスワード変更、ログインのない `GET` とログインを重ねる。止めない実際の重複として、`GET` 4件とログアウトも重ねる。古いIDが Redis に復活しない。古い Cookie が 401。止めた要求がセッションと CSRF の Cookie を返さない。通常のログアウトと再ログインが動作する。**同期点はスクリプトの実行中のみ隔離環境の `bootstrap/providers.php` に追加し、終了時に戻す。本番のコードは参照しない** |
| AUDIT-SESSION-03 | 応答の到着順とセッションの Cookie（`scripts/test-session-cookie-order.sh`、`scripts/test-session-browser.sh`、Pest。使い捨ての環境） | 完了した `GET` の応答を止め、ログアウトまたはパスワード変更の応答より後に届ける。curl は到着順に Cookie を適用する。実ブラウザは Chromium、Firefox、WebKit で、中継のプロキシが応答を止める（アプリの変更なし）。古いIDが Redis に復活しない。最終の Cookie で `auth/me` が 401。`csrf-cookie` は廃止済みのIDに Cookie を返さない。Cookie を消さない再ログインは、`Sec-Fetch-Site` を送るブラウザで 200、送らないクライアントで 419 となり、Cookie を消すと 200。止めない重複の頻度も記録する。古いIDで送った `csrf-cookie` が変更の後に処理されても、新しいセッションの Cookie が変わらないことを確認する |
| AUTH-E2E-01 | 実際のログイン画面（`scripts/test-login-browser.sh`、Vitest。使い捨ての環境と CI） | nginx が配信するビルド済みの画面を、Chromium、Firefox、WebKit で操作する。入力とクリックでログインし、「ようこそ」の画面に留まる。ログインの完了後に送った `auth/me` がすべて 200。再読み込みでログインが続く。ログアウトでログイン画面に戻り、再読み込みでも戻らない。ページの `Referrer-Policy` は `no-referrer` のまま |
| AUDIT-CSRF-01 | 419 と 401 の区別 | Cookie なし、セッションの不在・期限切れ、ログインのないセッションは、状態を変更する要求でも 401。ログイン済みのセッションで CSRF トークンなしは 419。ログイン API の CSRF トークンなしは 419。並行試験で 419 が出る場合は注記として記録する |
| AUDIT-WORKER-01 | キューの障害（`scripts/test-worker-failure.sh`。使い捨ての環境。工程1-6 で DB キュー向けに置き換えた） | [§19](#19-工程1-6-の分析とワークフロー-api-のテスト) を参照。Redis キューで再現した現象は [architecture.md §10](architecture.md) に記録している |
| AUDIT-E2E-01 | 実際の HTTP での通し確認（`scripts/test-auth-flow.sh`） | 工程1-2 の「監査ログが0件」の確認を、イベントが記録され `audit:verify --all` が成功する確認に置き換える |

**パスワード変更の障害テスト（AUDIT-PWCHG-01）：** 「注入」は `DatabaseTransactions` を使わない Pest のテストで、失敗する処理に差し替える。「実環境」は使い捨ての環境で実際の Redis を操作する（`scripts/` の通しテスト。実行前に確認を得る）。

| ケース | 期待結果 | テスト方法 |
|---|---|---|
| Redis への保留情報の保存の失敗 | **DB の変更なし、503**（RFC 9457 と `Retry-After`）。`password`、`password_changed_at`、2つの冪等性の列が不変で、`auth.password_changed` なし。同じキーの再試行で正常に変更できる | 注入：保留情報の保存を失敗させる。実環境：手順5の直前に Redis を停止する |
| 保留情報の保存後に DB のコミットが失敗 | **DB の変更なし。保留情報は認証に使われない。** 503。古いパスワードでログインでき、新しいパスワードでは 401。他のセッションは有効のまま。正式な指紋を外して保留の指紋だけを持つセッションは 401。重大ログに `outcome=password_change_rolled_back` | 注入：監査の書き込みと `UPDATE` を失敗させる |
| DB のコミット成功後に Redis が停止 | **変更は確定として扱い、取り消さない。** **503** と `Retry-After`。監査は1件で、再試行でも増えない。障害中は他の要求が 503 で、古いパスワードは使えない。セッションの保存が長時間待たない。**`NullSessionHandler` に切り替えない。保存していないセッションIDの Cookie を返さない。** サーバーログに `outcome=password_change_committed_session_failed` | 注入：手順8のセッションの書き込みと応答時の保存を失敗させる。実環境：コミットの直後に Redis を停止する |
| コミットの前後の区別 | コミット前の失敗はロールバックされ、再試行は通常の処理として1回だけ実行される。**コミット後の失敗は DB を取り消さず、再試行は再実行なしで 200。** ハッシュと `password_changed_at` が再試行で変わらない | 注入：コミットの前と後でそれぞれ失敗させる |
| 503 の案内 | **`PATCH /account/password` の 503 は、コミット前の失敗、コミット後の失敗、事前確認の失敗、入口の Redis の障害で `trace_id` 以外すべて同じ。** `detail` が「パスワード変更の結果を確認できませんでした。変更が確定している可能性があります。できるだけ早く、同じ内容・同じ冪等性キーで再試行してください。」と完全に一致する。パスワード失敗の文言を含まない。他の API の 503 の文言は変わらない | Pest |
| 再試行とセッション | **再試行時にセッションが利用できなければ 401 で、認証を成功扱いにしない。** 再試行がセッションを作らない。再ログインの後、DB の4条件がすべて一致すれば 200、1つでも一致しなければ変更済みと判断しない。古いキー、期限切れのキー、異なる内容は 200 にならない。再試行でセッションの保存に失敗すれば再び 503 で、DB は変わらない。パスワードと `Idempotency-Key` がログに出ない | 注入：セッションを削除して再ログインと再送を行う |
| Redis 復旧後の現在のセッション | **DB の確定状態と照合して維持できる。** 保留の指紋が DB のハッシュと一致し、最初の要求で正式な指紋へ昇格し、セッションIDが再生成される。他のセッションは 401（Redis の削除に依存しない） | 実環境：前のケースに続けて Redis を再開する。永続化ありの構成で行う |
| Redis の再起動で全セッションが消失 | **再ログインが必要。新しいパスワードでログインでき、古いパスワードでは 401。** パスワードの変更と監査は残る | 実環境：永続化なしで再起動する |
| 同じ変更要求の再送 | **二重変更と監査の重複を防止する。** 同じキー・同じ内容は同じ `password_changed_at` で 200、`auth.password_changed` は1件のまま、ハッシュは不変。**`new_password` のみ、`current_password` のみ異なる場合は、どちらも 409。** 期限切れと別のキーは通常の処理。同時要求（同じキー、別のキー）で1件のみ成功する。**最初の要求のコミット前に後続の要求が成功しない（待つ）。** 最初の要求がロールバックされると後続の要求が実行される。待ちの超過は 503 | Pest：実トランザクションと複数の接続。実環境：応答の後に再送する |
| 同時要求と保留情報 | **確定に使われる保留の値が上書きされない。** 2つの要求を行ロックの前後で競合させ、後の要求が保留の値を書き込まない。先の要求の確定の直後に Redis を止めても、現在のセッションが復旧後に維持される。同じセッションの別の要求（`GET /auth/me`）がセッションを保存しても、保留の値が消えない。**ヘッドのロックを保持したまま Redis へ通信しない** | Pest：実トランザクションと複数の接続。実環境：競合の直後に Redis を停止する |
| **A. 指紋の保存の成功後に DB がロールバック** | **成功済みと誤認しない。** 503。DB は不変で、キーが保存されない。残った指紋で認証されない。同じキーの再試行は通常の処理として1回だけ実行される。監査は再試行の成功の1件のみ | 注入：指紋の保存の後に `audit_append()` を失敗させる |
| **B. DB のコミットの成功後に HTTP の応答が失われた** | **二重に実行しない。** 同じキー・同じ内容の再試行は同じ `password_changed_at` で 200、ハッシュと監査の件数が不変。別のキーの再試行は 422 で、ハッシュが不変。セッションが指紋で維持される | 注入：コミットの後に応答を破棄して再送する。実環境：クライアントの接続を切断する |
| **C. 指紋が残ったまま DB の変更が失敗** | `UPDATE` のエラー、監査の失敗、確定の失敗のそれぞれで DB が不変。残った指紋が次の変更のハッシュと一致しない。指紋の消去に失敗しても安全性が変わらない | 注入：各段階を失敗させ、指紋の消去も失敗させる |
| **C'. コミットの応答が不明** | キーの読み直しで確定なら 200、キーがなければ 503。読み直しの失敗も 503。同じキーの再試行で正しく判定される | 注入：コミットの例外の後の行の状態を変えて確認する |
| **D-1. 指紋のキーの期限切れ** | 昇格の前に切れると、セッションが 401 になり（fail closed）、新しいパスワードで再ログインできる。パスワードは確定のまま | 注入：キーを削除する |
| **D-2. Redis の再起動** | 全セッションと指紋が消失し、再ログインが必要。新しいパスワードで成功し、古いパスワードは 401。変更と監査は残る | 実環境：永続化なしで再起動する |
| **D-3. 部分的なデータ消失** | 指紋のみ消失：コミット済みは 401、未コミットは影響なし。セッションのみ消失：401。いずれも DB の状態を変えない。Redis のキーの有無で変更の成否が変わらない | 注入：片方のキーのみ削除する |
| **E. コミット後に HTTP の応答が失われ、Redis の指紋も消失** | セッションは 401。新しいパスワードで再ログインでき、古いパスワードは 401。**変更済みと判断するのは次のすべてが一致した場合のみ：① 15分の期限内である ② `password_change_key_hash` が一致する ③ `new_password` が現在の `password` のハッシュと一致する ④ `current_password` が `password_change_previous_hash` と一致する。** Redis を空にしても同じ判定となる。ハッシュ、`password_changed_at`、監査の件数が不変。**完了済みのキーを Redis に保存していないことを確認する** | 注入：コミットの後に応答を破棄し、Redis のキーを削除して再ログインと再送を行う |
| E の否定の条件 | **どれか1つでも一致しなければ変更済みと判断しない。** ①期限切れ：列に値が残っていても照合せず、通常の処理で 422（再実行なし）。②キーの不一致：通常の処理で 422。③ `new_password` のみ不一致：409。④ `current_password` のみ不一致：409。いずれもハッシュと監査の件数が不変 | Pest：`password_changed_at` と各入力を変えて確認する |
| E の `APP_KEY` のローテーション | ローテーションの後は `password_change_key_hash` が再現できず、同じキーでも一致しない。セッションの指紋も同じ鍵に依存するため、既存のセッションは 401 となる。新しいパスワードで再ログインでき、再試行は 422 となり、**再実行されず、変更済みとも判断されない**（監査の件数が不変） | Pest：鍵を差し替えて再ログインと再送を行う |
| Redis の通信中の行ロック | **`PING` は行ロックの前に行われ、その失敗でロックを取得しない。同じ接続を再利用する（`CLIENT ID` の比較）。** ロックの取得後は生のクライアントのみを使い、**`command()` を使わない（静的検査でも確認する）。** `max_retries=0`、`read_timeout=0.9秒`。ロックの取得後に名前解決、接続の確立、自動再接続が起きない。書き込みの失敗で直ちにロールバックし 503 となる。**単調増加時計で全体の期限を判定し、1秒を超過した場合は、書き込みが成功していても成功扱いにせず、ロールバックして 503 となる**（時計を差し替えて確認する）。**残った指紋が正常な再試行を妨げない。後から適用された指紋で認証されない。** idle のタイムアウトは非常時の保護策として別に確認する。**`lock_timeout` が保持を止めない。** ヘッドのロックを保持しない。実際の保持時間を記録する | 実環境：Redis を無応答・停止にする。使い捨ての環境で行う |
| 変更前のハッシュの期限 | **期限切れのハッシュは、`scheduler` が止まっていて列に残っていても照合されず、`Hash::check` に渡らない。** 期限の判定が DB の時刻による。`scheduler` は期限切れの行のみ NULL にし、期限内の行を変更しない。別の変更で2つの列が同時に置き換わり、古いキーの再送で古いハッシュが照合されない | Pest：`password_changed_at` を過去にし、`scheduler` を実行しない |
| 冪等性の記録 | `password_change_key_hash` に平文のキーが含まれない。平文のパスワード、通常のハッシュ、パスワードの HMAC が保存されない。`password_change_previous_hash` が変更前の Argon2id ハッシュである。**応答、ログ、監査ログ、例外の情報にキーとハッシュが出ない（DB エラーを起こして確認する）。** `APP_KEY` の変更後は再実行されず通常の処理になる。`Idempotency-Key` がなければ 422 | Pest |

**AUDIT-LOAD-01 で確認する項目：**

| 項目 | 確認の内容 | 判断に使うもの |
|---|---|---|
| 同じ IP からの正常なログイン | NAT 配下を想定した利用者数と集中（始業時など）で、何人まで 429 にならないか | `AUDIT_LOGIN_IP_LIMIT_PER_MINUTE` |
| 実際の接続元 | nginx を直接、Vite proxy 経由、公開ポート経由で、`$request->ip()` がどの値になり、複数の利用者が同じ IP になるか | IP 単位の制限の有効性、`ip_address` の意味 |
| システムチェーンの処理量 | 匿名イベントの秒間件数と、応答時間・`55P03` の発生率 | `AUDIT_SYSTEM_CHAIN_LIMIT_PER_MINUTE` |
| 上限の超過時 | 未記録の件数が `audit.events_suppressed` と一致するか、応答が変わらないか | 検知の設計 |
| チェーンの分離 | システムチェーンへの集中で、組織チェーンの記録とログインの応答時間が悪化しないか | チェーンの分離 |
| 同じ組織への集中 | ログイン失敗の集中時の `55P03` の発生率、正しい利用者が競合の 401 を受ける頻度 | `lock_timeout`、R-14 |
| 増加量 | 上限での1日あたりの行数、ディスク使用量、ログの量、`audit:verify` の所要時間 | 上限、保持の方針 |
| Redis の障害時 | 応答までの待ち時間（実測：新しい接続で最大約5秒、接続済みで約21秒）、php-fpm の処理の滞留、集約後のログの量 | `REDIS_TIMEOUT`、`REDIS_READ_TIMEOUT`、`REDIS_MAX_RETRIES`、`LOG_AGGREGATION_INTERVAL_SECONDS`、R-20 |
| DB のタイムアウト | 通常の負荷での最も遅い文とロック待ち（誤って打ち切らない値か）、`55P03`・`57014` の発生率、無応答時の php-fpm のプロセスの枯渇までの時間 | [security-design.md §16.5.6](security-design.md) の暫定値 |

測定の結果は、暫定値の見直しの材料としてレビューに提出する。使い捨ての環境の結果は公開環境の性能を保証しないため、**公開環境の構成が決まった時点で再測定するまで、値を確定しない。**

**`DatabaseTransactions` のテストと業務トランザクションの区別：** `DatabaseTransactions` を使うテストでは、テスト用のトランザクションがあるため、トランザクションレベルが常に1以上になる。`recordAfterTransaction()` の「業務トランザクションの外」の確認がそのままでは失敗する。次のように区別する。

1. `AuditLogger` は `DB::transactionLevel()` を直接読まず、契約 `TransactionBoundary::businessLevel()` を通して確認する。
2. 本番の実装は対象の接続の `transactionLevel()` をそのまま返す。**環境（`APP_ENV`、`runningUnitTests()`）による分岐を持たない。**
3. テストの実装は `tests/` に置き（`autoload-dev` のため本番には含まれない）、`TestCase` が `DatabaseTransactions` の開始後のレベルを基準として記録し、`transactionLevel() - 基準` を返す。テストのコンテナにのみ登録する。
4. これにより、テスト本体の `DB::transaction()` はレベル1以上（業務トランザクション）、それ以外はレベル0（外）として、本番と同じ判定になる。

**`DatabaseTransactions` で確認できないことは、使わずに実行する：**

- AUDIT-TX-01、AUDIT-CONC-01 は `DatabaseTransactions` を使わず、本番の `TransactionBoundary` と実際のコミットで実行する（テスト用のトランザクションの中では、コミットの順序とヘッドのロックの解放を再現できないため）。
- 実際の DB エラーを起こす場合も `DatabaseTransactions` を使わない（PostgreSQL ではエラーでテスト用のトランザクション全体が中断されるため）。AUDIT-FAIL-01 の応答の確認は失敗する書き込み処理への差し替えで行い、実際のエラー（別の接続でヘッドをロックした `55P03`）を少なくとも1件、実トランザクションで確認する。
- コミットされた行は削除できないため、テストごとに別の組織を使う。システムチェーンは共有されるため、件数を固定した確認を行わず、検証の成功と増分のみを確認する。テスト用DBのスキーマは実行ごとに `migrate:fresh` で作り直される。
- arch テストで、`app/` が `tests/` を参照しないこと、`App\Audit` が `APP_ENV`・`runningUnitTests()` を参照しないことを確認する。

**工程1-1・1-2 のテストの変更：** `app` ロールで `audit_logs` に INSERT している次のテストは、工程1-3で書き換える。`tests/Pest.php` の `insertAuditLog`・`auditValues`・`AUDIT_INSERT_COLUMNS`、`AuditLogTamperTest`（通常の INSERT の成功を前提とする部分）、`TablePrivilegeTest`（列単位の INSERT）、`ConstraintTest`（`audit_logs` の制約）、`MigrationTest`（列の一覧。チェーンの列がないことの確認）、`LoginAndSessionTest` と `scripts/test-auth-flow.sh`（監査ログが0件であることの確認）、`PasswordTest` と `scripts/test-auth-flow.sh` のパスワード変更（`Idempotency-Key` が必須になるため）。

**検証の結果（2026-11-04。使い捨ての環境）：** 試作とコピーしたコードでの確認であり、工程1-3の実装のテストを置き換えない。

| 項目 | 結果 |
|---|---|
| 1秒の要件 | 生のクライアント、`max_retries=0`、`read_timeout=0.9秒` で、切断・停止で0秒台、無応答で0.901秒。`command()` は再接続して5.007秒 |
| `SF001` | `errorInfo[0]` に届く。他の UNIQUE 違反は `23505` のまま。並行時も1件のみ |
| 行ロックの解放 | Redis の失敗で1.002秒、idle のタイムアウト、プロセスの強制終了で解放。クライアントのネットワーク断は idle のタイムアウトが必要 |
| `53100` と領域 | テーブルの領域、一時ファイルの領域、WAL の領域で動作が異なる（[security-design.md §16.5.1](security-design.md)） |
| Redis の障害の実際の応答 | 現在のコードでログインと認証済み API は 500、liveness は 200、readiness は 503。復旧後に通常へ戻る |
| セッションの全体の保存 | 同時の要求で保留の値が消える（専用のキーへの分離の根拠） |
| V5〜V7 | PostgreSQL と PHP で一致 |
| `DatabaseTransactions` | 基準レベル1、`DB::transaction` の中は2、なしは0。SQL エラーの後は `25P02` |
| Docker | `restart: unless-stopped` で `unhealthy` でも再起動しない |
| 実行ユーザー | PHP のイメージは `app`（uid 1000）。`/tmp` は `sys_get_temp_dir()` で書き込み可能 |

**検証の結果（2026-11-05。隔離した環境）：** 工程1-3の実装に対する実際の障害の確認である。

| 項目 | 結果 |
|---|---|
| PostgreSQL の停止の待ちの内訳 | DNS の失敗が1回 3.1〜4.0秒、閉じたポートの TCP の拒否が 0.000秒、無応答のサーバーが 2.0秒（`ATTR_TIMEOUT`）。**原因は DNS と Laravel の再試行（1文で4回の接続）** |
| 修正の前後 | 最初の要求 約26秒→7.2秒。フラグ中の認証済み API 14.4秒→0.019秒。フラグ中のパスワード変更 12.5秒→0.018秒 |
| フラグの期限切れの同時の8要求 | 1要求のみ 4.0秒、他の7要求は 0.04秒以下。すべて 503 |
| Redis の停止・無応答 | 全経路で 503 と `Retry-After: 30`（停止 3.1〜4.0秒、無応答 1.0秒）。復旧後は追加の操作なしに正常 |
| readiness のログ | 3回の呼び出しで `readiness.redis.outage_started` が1件。`storage` は数えない |
| 実 HTTP の並行要求 | 同じキー・同じ内容で全要求が同じ時刻、異なる内容の負けは 409、別のキーは 1件のみ 200、監査はいずれも1件 |
| 修正前のログアウトと並行する `GET` | **止めた3周回と、止めない重複の5周回のすべてでセッションが復活した**（保存の内容はログイン済み、古い Cookie で 200、`GET` が古い Cookie を返す） |
| 修正後の `test-session-race.sh` | 同じコードで2回実行し、各回 **382件合格、0件失敗。** 止めた試験は3種類を各10周回×2回（ログアウト、パスワード変更、ログイン）、止めない重複は20周回×2回（`GET` は計160件） |
| 陰性対照 | 隔離環境で廃止の記録のみを一時的に無効にし、3周回と5周回で実行すると **51件失敗**（ログアウトの全周回でセッションが復活し、パスワード変更でも古いIDが復活した）。試験が競合を検出できることの確認であり、終了後にファイルが元に戻ることを確認した |
| 止めない重複の `GET` の結果 | 2回とも 200 が66件、401 が14件。**セッションの Cookie を返した `GET` は80件中20件と24件。** これらがログアウトの前後のどちらに完了したかは区別していない。すべての周回で、終了後にセッションは存在せず、古い Cookie は 401 |
| 応答の到着順（curl。`test-session-cookie-order.sh`） | **642件合格、0件失敗。** 止めた試験はログアウト、パスワード変更の各20周回。`GET` はすべて後に到着し、Cookie は古いIDになった（40/40）。`auth/me` は 401、古いIDは Redis になく、廃止の記録の残りは約2098秒。パスワード変更では、新しいセッションは Cookie の写しで 200 のまま（20/20）。`csrf-cookie` は Cookie を変えず、古い Cookie のままの再ログインは 419（40/40）、Cookie の消去後は 200（40/40）。止めない試験（各20周回を2回）では、後に到着した `GET` は0件、最終の Cookie が古いIDの周回は0件 |
| 実ブラウザ（`test-session-browser.sh`） | **128項目合格、0件失敗。** Chromium 各20周回、Firefox と WebKit 各5周回（いずれもログアウト、パスワード変更）。**止めた応答はすべて Cookie を上書きしたが、認証は復活しなかった。** `auth/me` は 401、古いIDは Redis になく、`csrf-cookie` は Cookie を変えず、再ログインは 200 でそのログインも動作した（`Sec-Fetch-Site: same-origin` のためトークンを照合しない）。パスワード変更の新しいセッションはサーバーに残った。`Sec-Fetch-*` を除いた Chromium（各5周回）は、再ログインが 419、Cookie の消去後は 200 |
| 不採用とした `csrf-cookie` の修正（参考） | 廃止済みのIDに新しいIDを発行する修正を検証した。curl と `Sec-Fetch-*` なしの Chromium で、Cookie を消さない再ログインが 200 になった。一方、古いIDで送った `csrf-cookie` が変更の後に処理されると、3ブラウザの全周回（各5周回×3回）で新しいセッションの Cookie が匿名のIDに上書きされ、`auth/me` が 401 になった。このためコードから削除した。この結果は現在のコードのものではない |
| 実ブラウザの止めない重複（Chromium、各10周回×2回） | 最終の Cookie が古いIDの周回は0件。ログアウト後の `auth/me` は 401、パスワード変更後は 200。**同一マシン上の結果であり、ネットワークの遅延がある環境の頻度ではない。** Chromium は同じURLの要求を HTTP キャッシュのロックで直列化する（完了しない要求の間、次の要求が20秒待つことを単独の試験で確認）。当初は同じURLで実行していたため、`GET` ごとに別のURLに直して再実行し、結果は同じだった（ログアウトは 200 が10件と 401 が30件、パスワード変更は 200 が40件） |
| 短縮後の全試験（新しいボリューム、下の実行手順） | **22.5分（短縮前は95分）。** Pest 570件、`verify-infra` 54件×2回、`test-auth-flow` 75件、`test-session-invalidation` 23件、`test-password-concurrency` 132件、`test-session-race` 382件、`test-session-cookie-order` 642件と止めない試験のみの122件、`test-failure-modes` 185件。いずれも失敗0。`test-session-browser` はこの実行では試験の誤りによる6件の失敗があり、期待値を直して同じ環境で再実行し、0件失敗を確認した（全周回 128項目と止めない試験のみ）。カウンタをリセットせずに35回試すと 401 が30件、429 が5件で、レート制限の動作は変わっていない |
| 実際のログイン画面（`test-login-browser.sh`） | **修正前は3ブラウザとも、ログイン後の `auth/me` が 401 となり、ログイン画面に戻った（15件失敗）。** 修正後は3ブラウザとも合格し、4回の実行で同じ結果だった。Vitest は修正前に1件失敗、修正後に36件合格。curl は `Origin` と `Referer` を手で付け、`test-session-browser.sh` は `Referrer-Policy` のないページから実行していたため、検出できなかった |
| 遅れた `csrf-cookie`（3ブラウザ、各5周回） | 古いIDで送り、パスワード変更の後に処理させた。すべての周回で Cookie は変わらず、`auth/me` は 200、新しいセッションはサーバーに残り、古いIDは復活しなかった |

**使い捨ての環境での全試験の実行手順：** 次の順に1回ずつ実行する。`SECUREFLOW_ALLOW_FAILURE_INJECTION=<プロジェクト名>` を付ける（`test-auth-flow.sh` と `verify-infra.sh` は付けずに実行する）。

1. `verify-infra.sh`、`test-auth-flow.sh`、`test-login-browser.sh`、`test-session-invalidation.sh`、`test-password-concurrency.sh`、`test-session-race.sh`
2. `test-session-cookie-order.sh`、続けて `HELD_ROUNDS=0 test-session-cookie-order.sh`
3. `test-session-browser.sh`、続けて `ROUNDS=0 OTHER_ROUNDS=0 test-session-browser.sh`
4. `test-failure-modes.sh`、`verify-infra.sh`

応答を止める試験は結果がタイミングに左右されないため1回とし、止めない試験のみを2回実行する。周回数の既定値（応答を止める試験は20周回以上）は下げない。

ログインのレート制限（1アドレスにつき毎分30回）は、固定の待機の代わりに、カウンタをリセットして次の周回に進む（`scripts/lib/login-limit.sh`）。上記のプロジェクト名の指定がある場合のみ動作し、ない場合は従来どおり61秒待つ。既定のプロジェクトでは常に動作しない。制限そのものは変更せず、`test-auth-flow.sh` では使わない。

**セッションの競合の検証の区分（2026-11-05）：** 検証の方法を次のとおり区別する。下の区分を超えて検証済みとして扱わない。

| 区分 | 項目 |
|---|---|
| 実 HTTP で並行して検証 | 止めた `GET` とログアウト、パスワード変更、ログイン（ログインのないセッション）。止めない `GET` 4件とログアウト。同じセッションのパスワード変更の4並列（`test-password-concurrency.sh`：200 が1件、401 が3件、有効なIDが1つ）。応答の到着順（`test-session-cookie-order.sh`）。いずれも curl によるもので、ブラウザではない |
| 実ブラウザで検証 | 応答の到着順とログアウト、パスワード変更、遅れた `csrf-cookie`（Chromium、Firefox、WebKit）。止めない重複（Chromium のみ）。いずれも `fetch` を直接実行したものであり、実際の画面の操作ではない。接続先は `http://localhost` である |
| Pest の疑似競合でのみ検証 | 処理中の要求の途中で廃止された場合の保存の拒否と Cookie。すでに終了されたセッションの終了で新しいセッションを作らないこと。ログイン済みのセッションからのログインでの廃止。新しいIDの保存に失敗した場合に権利を返すこと。Redis の実際の接続に対する Lua の書き込みの拒否は Pest で確認したが、並行ではない |
| 逐次の実行でのみ検証 | 通常のログアウトと再ログイン。パスワード変更後の他のセッションの 401（`test-session-invalidation.sh`、`test-auth-flow.sh`） |
| 未検証 | 下の未検証事項の表のとおり |

**未検証事項：** 次は未検証である。検証済みとして扱わない。使い捨ての Docker 環境を使う場合は、**実行の前に確認を得る。**

| 項目 | 内容 |
|---|---|
| PHP-FPM のワーカーの枯渇時の liveness | 再現し、測定した（[§17](#17-audit-load-01-の測定結果)） |
| 指紋のキーと廃止の記録の有効期限 | 実際の Laravel のセッションとの併用は実 HTTP で検証した。実環境での期限の満了（指紋のキー、15秒の優先の期限、`session_retired`）は未検証 |
| 実 HTTP でのログアウトの同時実行 | 同じセッションのログアウトを並行して実行する場合。Pest の疑似競合のみ |
| `GET` 以外の並行要求とログアウト | 止める試験と重複の試験はいずれも `GET` のみで行った。`POST`・`PATCH` は同じ経路だが未実行 |
| 廃止の記録の保存と削除の間の Redis の実障害 | Pest の注入のみ |
| Cookie の上書きの実環境での頻度 | ネットワークの遅延がある環境、複数のタブ、https（[security-design.md §16.5.5](security-design.md) の残る制約）。同一マシン上では発生しなかった |
| 実際の画面の操作 | ログインからログアウトまでは AUTH-E2E-01 で確認した。パスワード変更の画面、遅れた応答と組み合わせた画面の動作、Vite の開発サーバー（5173）経由、`Sec-Fetch-Site` を送らない環境で古い Cookie が残った場合の画面の表示は未確認 |
| 非 localhost の http での実ブラウザ | ブラウザが `Sec-Fetch-*` を送らない状況は、プロキシでヘッダを除いて模擬した |
| 回復の確認の全体の動作 | 同時実行と排他の期限切れ、再読み取りの不一致、実際の `53100` からの回復。組織チェーンのみの障害（他は工程1-3の Pest で確認済み） |
| Vite proxy 経由の接続元 | 未測定 |
| libpq の言語設定 | 文言の変化（原因の分類のみに影響） |
| 処理時間（AUDIT-TIME-01） | 工程1-3の実装が必要 |
| 負荷試験（AUDIT-LOAD-01） | 実施した（[§17](#17-audit-load-01-の測定結果)）。公開環境での再測定、WAL の増加量は未実施 |
| フラグが立つ前の同時の要求 | DB の停止の直後は、最初のフラグが立つまで各要求が接続を試みる。単一化しているのはフラグの期限切れの後のみで、その間の PHP-FPM の占有は未測定 |
| 行ロック中とコミット直後の Redis の実障害 | 無応答の試験ではセッションの読み取りで先に失敗する。Pest の注入と設計時の試作でのみ確認 |
| 実際の Redis の認証エラー、永続化なしの再起動 | 未実施 |
| R-14 のタイミング差 | 未測定。**未解消の残存リスクとして維持する** |
| セッションの保存のタイムアウトの最終値 | 実装時に決定する |
| コミット後のセッションの保存の例外と Cookie | 応答時の保存の例外で `Set-Cookie` が出ないことと 503 は、Pest の注入でのみ確認した。実際の Redis の障害でのコミット直後の確認は未検証（`NullSessionHandler` は禁止） |
| DNS を含むプローブ全体の期限 | **未保証** |
| TCP の設定の実際の接続への適用 | 試作では実測したが、実装の接続では未確認 |
| WAL 枯渇後の具体的な復旧手順 | 運用設計の課題。`restart: unless-stopped` の下の再起動の繰り返しも未検証 |
| Redis の送信バッファが詰まる場合、TLS | 未測定 |

**使い捨てのDB：** シーケンス・DDL・INSERT・ROLLBACK を伴う確認は、テスト用DBか使い捨てのDBでのみ行い、開発用DBでは行わない。

## 16. 工程1-4 の AI 基盤のテスト

実際の AI には接続しない。DB を変更せず、migration も伴わない。

| ID | 対象 | 内容 |
|---|---|---|
| AI-CAT-01 | ActionCatalog | [architecture.md §8](architecture.md) の9種類の操作・判定・導出権限が表のとおりで、他にない。未知の値（大文字、前後の空白を含む）を知らない |
| AI-OUT-01 | OutputValidator（スキーマ・許可リスト） | [security-design.md §7](security-design.md)。不正な JSON、未知のキー、欠けたキー、型の違い、件数と長さの上限（文字数）、空白のみ、制御文字、大きさの上限、配列をオブジェクトで書いた場合を、`AI_INVALID_OUTPUT` で拒否する。未知の操作は拒否し、禁止操作は拒否せず `forbidden` とする。権限はカタログから導出する。例外に AI の出力を含めない |
| AI-GW-01 | AiGateway | タイムアウト・429・5xx のみ、指数バックオフ（1秒、2秒）で計3回まで試みる。拒否された要求は再試行しない。最長の所要時間（既定値で93秒）を返す |
| AI-MOCK-01 | MockAiProvider | [§4](#4-モックaiのシナリオ) の13シナリオ。入力でシナリオを切り替えられない。要求に tools や利用者の欄がない。`app/Ai` がネットワーク、プロセス、ファイルに触れない |
| AI-CONF-01 | 起動時の設定検証 | [architecture.md §11](architecture.md)。Web の起動、worker、scheduler が、未対応の値と本番相当の環境の `mock` でエラーになる。別プロセスで実際に起動して確認する。管理コマンドは動作する。`AiProvider` の解決時にも拒否する。メッセージに設定値を含めない |
| ST-07（AI 出力） | [§5](#5-セキュリティテストケース) | 不正な JSON を、ゲートウェイの再試行なしに拒否する。要求側の 422 は工程1-6 |

**工程1-4 では未対応のシナリオ：** `script_tag`・`secret_leak`・`canary_leak` の本文と `permission_inflation` の finding は工程2-4 の対象であり、**工程1-4 の検証を通過する。** この事実を試験（`NOT YET, step 2-4`）に記録しており、工程2-4 でこの試験を書き換える。合格は、これらを防いでいることを意味しない。`permission_inflation` は、AI の申告が導出権限に影響しないことのみを確認する。

## 17. AUDIT-LOAD-01 の測定結果

2026-11-06 に使い捨てのクローンで測定した（`scripts/test-audit-load.py`）。負荷の項目は2回、DB の凍結はクライアント20で2回（凍結中の接続数の記録は2回目のみ）、他の障害の項目は1回実行した。**値は Docker Desktop（WSL2、16コア）の同じマシンの上での結果であり、開発用イメージを使っている。公開環境の性能を示さず、暫定値を確定しない**（[§15](#15-工程1-3-の監査ログのテスト)）。

### 17.1 暫定値の確認

| 項目 | 結果 | 判断の材料 |
|---|---|---|
| 接続元 | 公開ポート経由は全員が `172.24.0.1`（Docker のゲートウェイ）、Vite proxy 経由は全員が `172.24.0.4`（frontend コンテナ） | IP 単位の制限は、現構成では全利用者の合計の上限である |
| 同じ IP からの正常なログイン | 60人の集中で200が30件、429が30件。毎分25回の間隔では全件200 | 1分間に31人目から拒否される。30回/分を変更する判断は、接続元の取得方法を確定する時点で行う（R-17） |
| HTTP の処理量 | 25〜27件/秒で頭打ち。クライアント1で p50 約200ms、40で約1.6秒。エラーなし | 上限は php-fpm の10プロセスと Argon2id であり、DB ではない |
| DB のみの処理量（`audit_append`、pgbench） | 710〜800件/秒。クライアント32まで失敗0件 | 600件/分（10件/秒）の約70倍 |
| 上限の超過 | 応答2,996件で記録1,200件・未記録1,796件、応答3,213件で記録1,200件・未記録2,013件。**いずれも差0件。** 応答本文は1種類 | 設計どおり |
| チェーンの分離 | DB のみ：組織チェーンの平均は単独で1.3〜1.5ms、システムチェーンに16クライアントの集中で1.8〜1.9ms。HTTP：組織チェーンの p50 は約230msから、別のチェーンの負荷で約400ms、同じチェーンの同量の負荷でも約400ms | チェーンの間の待ちは見られない。HTTP の悪化の原因は php-fpm の混雑である |
| 同じ組織への集中 | ログイン失敗の集中の中の正しいログインは計718件で**すべて200**。失敗40クライアントで p50 は約1.6秒 | 誤った401は0件。遅くなることは防げない |
| DB のタイムアウト | 負荷の中では `55P03`、`57014`、デッドロック、1秒を超えるロック待ちは0件。HTTP の負荷での `audit_append` は最長47ms、DB のみの試験を含めて最長586ms | 暫定値（関数の `lock_timeout` 2秒、`statement_timeout` 5秒）で誤って打ち切られない |
| 増加量 | 1行約700バイト（索引を含む）。上限で約86万行/日、約600MB/日、約18GB/30日。nginx のログは1ログインあたり約130バイト（上限で約110MB/日の概算）。app のログはほぼ増えない。組織チェーンには上限がない | 600件/分を緩める前に保持の方針が必要 |
| `audit:verify` | 43万行で7.2秒。検証は成功 | 30日分（約2,600万行）で約7分の推定。メモリは未測定 |

### 17.2 実際の障害

Redis の停止（`docker compose stop`）と凍結（`docker compose pause`）、PostgreSQL の凍結を、負荷の中で起こした。**障害中の要求は 503 または 504 となり（fail closed）、401 は回復の後に処理された要求にのみ返った。回復後に `audit:verify` は成功した。**

| 障害 | 負荷 | 障害の開始時に処理中だった要求 | 障害中の要求 | `/health/live` | 回復 |
|---|---|---|---|---|---|
| Redis の停止 | クライアント20 | 最長21.8秒 | 503。p50 3.1秒、最長9.6秒 | 200。p50 3.7秒、最長4.9秒 | 1秒未満で401 |
| Redis の凍結 | クライアント20 | 最長12.2秒 | 503。p50 2.0秒、最長11.1秒 | 200。p50 1.4秒、最長2.0秒 | 1秒未満 |
| Redis の凍結 | クライアント2 | 最長11.2秒 | 503。p50 1.0秒 | 200。12ms | 1秒未満 |
| DB の凍結 | クライアント2 | 1件が504（60秒） | 503。p50 18ms | 200。12ms | 7.0秒 |
| DB の凍結 | クライアント20 | 5〜9件が504（60秒）。凍結中の接続6（2回目） | 503。p50 88〜371ms | 200。1回目は p50 0.8秒、最長3.6秒。2回目は p50 86ms | 9.6〜10.2秒 |
| **DB の凍結** | **クライアント40** | **全ワーカーが停止（凍結の間ずっと接続10）** | **150秒の間、504のみ。凍結の解除まで処理された要求なし** | **504（60秒）** | 4.9秒 |

回復は復旧のコマンドの完了からの時間である。DB の回復は DB unavailable のフラグの有効期間（30秒）の残りによって変わる。app のログは各シナリオで3〜28行、0.6〜6KB であり、要求の数に比例して増えなかった。DB の凍結の解除の瞬間に、凍結中に期限が切れた文が `55P03`（1件）と `57014`（5件）で取り消された。監査の追記も含まれるが、回復後の検証は成功した。

**ワーカーの枯渇（R-19）：** DB のプロセスが止まってカーネルのみが応答する間、接続済みのワーカーは凍結の解除まで戻らない。処理中の要求の数だけワーカーを失い、全ワーカーが処理中であれば要求を全く処理できず、liveness と readiness も nginx の `fastcgi_read_timeout`（60秒）で 504 となる。**この間も Docker の app の health は `healthy` のままであった。** healthcheck は php-fpm の TCP の受付と `artisan` の起動のみを確認し、ワーカーの空きを確認しないためと考えられる。凍結の解除で自然に回復した。

**測定していないもの：** WAL の増加量、ネットワークの断（AUDIT-DBTO-01 で確認する）、複数の接続元、https、本番用イメージ、DB の停止（凍結のみ測定した）。

## 18. 工程1-5 のワークフロー基盤のテスト

ワークフローの API は工程1-6 で追加する。HTTP の応答は、テストの中だけで登録するルート（`routes/api.php` と同じミドルウェア）で確認し、本番のアプリケーションにはこのルートを持たせない。

| ID | 対象 | 内容 | ファイル |
|---|---|---|---|
| WF-SM-01 | 状態遷移 | 7状態×8イベントの56通りすべて。許可の表は実装と別にテストに書く。Approved・Running に承認を経ずに到達できない | `tests/Unit/Workflow/WorkflowStateMachineTest.php` |
| WF-TR-01 | 遷移の適用 | トランザクションの外では実行できない。不正な遷移は何も変えない。古い読み取りは 409 `REVISION_CONFLICT`。別の組織のワークフローは見つからない | `tests/Feature/Workflow/WorkflowTransitionTest.php` |
| WF-CON-01 | 並行性（実プロセス、実コミット） | 並行する4つの遷移のうち1件のみ成功する。遷移中の行はロックされる。トランザクションと一緒にロールバックされる。同じリビジョンの2件の決定のうち1件のみ成功する | `tests/Concurrency/WorkflowConcurrencyTest.php` |
| WF-HASH-01 | PlanHasher | Python の独立した実装（`tests/Fixtures/generate-plan-hash-vectors.py`）の固定ベクトルと一致する。`jsonb` の往復でキーの順序が変わっても一致する。承認の対象のすべての項目の変更でハッシュが変わる。設計にない項目、NUL、不正な UTF-8 を拒否し、エラーに内容を含めない | `tests/Unit/Workflow/PlanHasherTest.php` |
| WF-DB-01 | DB の制約 | 改変拒否、複合外部キー、列単位の権限、CHECK、一意制約、未検査の行。ST-21・ST-38 の DB 部分 | `tests/Feature/Workflow/WorkflowSchemaTest.php`、`tests/Feature/Database/TablePrivilegeTest.php` |
| WF-MIG-01 | マイグレーション | 全体の往復。`workflow_revisions`・`approvals` に行があれば `down` が中断する | `tests/Feature/Database/MigrationTest.php` |
| ST-06, 12, 21, 23, 37 | Policy | 操作ごと、ロールごとの判定を手で書いた表と比較する。ロールの変更、無効化、ロック | `tests/Security/WorkflowPolicyTest.php` |
| ST-23 | 組織スコープ | 2組織×全モデル。文脈がなければクエリを実行しない。別の組織の行を読めず、更新できず、作成できず、移動できない。**全エンドポイントの確認は工程1-6** | `tests/Isolation/WorkflowIsolationTest.php` |
| ST-12, 21, 23 | HTTP の応答 | 別の組織、別の member、存在しない ID の 404 の本文が `trace_id` を除いて同一である。UUID でない ID も 404。403、409 の RFC 9457 形式。応答に内部情報と内容を含めない | `tests/Feature/Workflow/WorkflowHttpTest.php` |
| ST-34 | ルート | 全ルートの認証、組織の文脈、Policy を自動検査する。欠けたルートを実際に登録して検出できることも確認する。組織の文脈がルートモデルバインディングより先に設定される | `tests/Security/RouteAuthorizationTest.php` |

## 19. 工程1-6 の分析とワークフロー API のテスト

| ID | 対象 | 内容 | ファイル |
|---|---|---|---|
| WF-JOB-01 | 分析の処理 | Workflow、Revision #1、Tasks、監査記録が1つのトランザクションで保存される。権限は AI の申告でなくサーバーが導出する。再実行しても二重に作らない。他の処理が取得した行に触れない。ST-07（不正な出力で失敗し、何も保存しない）。監査を記録できなければ何も保存しない | `tests/Feature/Workflow/AnalysisJobTest.php` |
| WF-QUEUE-01 | キュー | ジョブと行が一緒にコミット・ロールバックされる。ジョブは ID のみを持つ。実際の worker で処理される。時間制限の順序（AI の最長 < ジョブ < `retry_after`、停滞の判定 > ジョブ）。戻ってきたジョブが `failed_jobs` と業務の失敗を分けて記録する | 同上、`scripts/test-compose-env.sh` |
| WF-REC-01 | 停滞回収 | 動作中のものを回収しない。全組織の停滞を回収する。回収の後に戻った処理は何も保存しない。成功は取り消されない | 同上 |
| WF-API-01 | 分析の API | 入力をどこにも保存しない（行、ジョブ、ログ、全テーブル）。エラーに入力を含めない。長さの上限、未知の項目、10回/分。参照は依頼者本人のみ（admin も 404） | `tests/Feature/Workflow/AnalysisApiTest.php` |
| WF-API-02 | ワークフローの API | 一覧の範囲、絞り込み、カーソル。編集で新しいリビジョンとハッシュ。古いリビジョンは変わらない。ST-09、ST-17。サーバーが決める項目を受け付けない。`If-Match` の 428 と 409。タスクの上限と下限。別のワークフローのタスクは 404。監査の失敗で変更が残らない | `tests/Feature/Workflow/WorkflowApiTest.php` |
| ST-23, ST-34 | 全エンドポイント | リソースを取る全エンドポイント×別組織の3ロールが 404 で何も変えない。一覧とルート一覧を照合し、新しいエンドポイントの追加漏れを検出する | `tests/Isolation/EndpointIsolationTest.php` |
| WF-UI-01 | 画面 | 常に警告を表示する。応答の検証。AI やユーザーの文字列をマークアップとして描画しない。`If-Match` と送信する項目。競合で入力を失わない。ポーリングの停止 | `frontend/src/features/workflows/workflows.test.tsx` |
| WF-FLOW-01 | 実 HTTP と実 worker | 入力から編集まで。**入力が DB の全データとログに現れない**ことを `pg_dump` とログで確認する。チェーンの検証 | `scripts/test-workflow-flow.sh`（CI） |
| AUDIT-WORKER-01 | 実際の障害（使い捨ての環境） | 待機中の Redis の強制終了でジョブが残り1回実行される。死んだ worker のジョブが戻ると行が失敗になる。ジョブのない停滞を実際の scheduler が回収する。PostgreSQL の再起動から回復する。時間制限を超えたジョブが止まる | `scripts/test-worker-failure.sh` |

## 20. 工程1-7 のダッシュボードのテスト

| ID | 対象 | 内容 | ファイル |
|---|---|---|---|
| DASH-01 | 集計値 | 固定データで、手で書いた期待値と比較する。2組織、3ロール。member は自分の分のみ、admin / auditor は組織全体。別の組織を数えない。月の境界（UTC） | `tests/Feature/Dashboard/DashboardSummaryTest.php` |
| DASH-02 | 未実装の項目 | `null` を返し、0 を返さない。画面は「未実装」と表示する | 同上、`frontend/src/features/dashboard/dashboard.test.tsx` |
| DASH-03 | 最近の操作 | member は自分の操作のみ。許可した種類のみ。システムチェーンを含まない。IP と metadata を返さない。新しい順に10件 | 同上 |
| DASH-04 | 画面 | 数値とグラフの表の対応。応答の検証。文字列をマークアップとして描画しない | `frontend/src/features/dashboard/dashboard.test.tsx` |
| AUTH-E2E-01（拡張） | 実ブラウザ3種 | ログインから入力、分析、編集を経てダッシュボードの集計とグラフまでの通し確認。画面の例外がないこと | `scripts/test-login-browser.sh` |
