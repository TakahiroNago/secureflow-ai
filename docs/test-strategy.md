# SecureFlow AI — テスト戦略

- 版：v1.3（2026-11-04）
- 状態：確定（v1.3：工程1-2 の認証テストを追加。v1.2：工程1-1 の設計レビューと検査の修正を反映。v1.1：Q-D13・Q-PII・D11・Phase 0 追加条件を反映）

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

MockAiProvider は入力中の制御用マーカーまたはテスト設定で応答を切り替える（本番では mock は無効）。

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
| DB-PRIV-02 | `audit_logs` の INSERT | app の通常の INSERT は成功。`nextval()` と、任意の `id` を指定した INSERT（`OVERRIDING SYSTEM VALUE` を含む）は拒否される |
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
