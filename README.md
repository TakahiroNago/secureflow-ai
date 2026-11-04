# SecureFlow AI

AI業務自動化・セキュリティ管理プラットフォーム（AI Automation & Security Platform）

> 「AIに仕事を任せる。しかし、AIに無制限の権限は与えない。」

AI が業務内容を分析・提案し、セキュリティレイヤーが処理内容と権限を検証し、重要な操作は人間の承認を経て実行する Web アプリケーションです。

**現在の状態：Phase 0（開発基盤）完了時点。** 業務機能（認証・AIワークフロー・承認・監査ログ等）は Phase 1 以降で実装します。計画は [docs/development-roadmap.md](docs/development-roadmap.md) を参照してください。

---

## アーキテクチャ概要

```
Browser (React SPA)
   │  同一オリジン（Cookie セッション + CSRF、CORS 無効）
   ▼
nginx 127.0.0.1:8080 ── /api, /sanctum ──▶ php-fpm (Laravel API)
   │                                         │
   └─ / (frontend/dist)                      ├─▶ PostgreSQL（app ロール：DML のみ）
                                             ├─▶ Redis（セッション/キャッシュ/キュー）
                                             └─▶ AI プロバイダ（Phase 1 はモックのみ）
worker / scheduler（Laravel Queue / Scheduler）
migrate（owner ロール：マイグレーション専用・都度実行）
```

| 防御層 | 内容 |
|---|---|
| L1 入力検査 | 個人情報のマスキング、認証・秘密情報の検出による停止、プロンプトインジェクション検出（検出は完全ではない） |
| L2 AI 能力の剥奪 | AI にツール実行・DB・外部通信の権限を与えない（最終防御層） |
| L3 出力検証 | JSON スキーマ・操作許可リスト・機密情報・HTML 除去 |
| L4 人間の承認 | 実行計画の SHA-256 ハッシュに紐付け。自己承認禁止 |
| L5 実行時再検証 | 禁止操作の実行ハンドラはコード上に存在しない |

詳細：[architecture](docs/architecture.md) / [database](docs/database-design.md) / [api](docs/api-design.md) / [security](docs/security-design.md) / [threat model](docs/threat-model.md) / [test strategy](docs/test-strategy.md) / [requirements](docs/requirements.md)

## ディレクトリ構成

```
backend/    Laravel API（app/, config/, routes/, tests/）
frontend/   React + TypeScript + Vite + Tailwind CSS
docker/     nginx / php / postgres の設定と初期化スクリプト
scripts/    init-env.sh（.env 生成）、add-test-owner.sh（既存環境の更新）、verify-infra.sh（基盤検証）、check-published-ports.sh（公開ポート検査）、test-*.sh（検査の負のテスト）
docs/       要件定義・設計書
.github/    GitHub Actions（CI）
```

## 採用バージョン

Phase 0 時点で実際に採用し、固定しているバージョンです。

| 分類 | コンポーネント | バージョン | 固定箇所 |
|---|---|---|---|
| コンテナ | PHP (fpm, Alpine) | 8.4.27（alpine3.24） | `docker/php/Dockerfile` |
| | Composer | 2.11.1 | `docker/php/Dockerfile` |
| | phpredis / PCOV | 6.3.0 / 1.0.12 | `docker/php/Dockerfile` |
| | PostgreSQL | 18.6（alpine3.24） | `compose.yaml` |
| | Redis | 8.10.3（alpine3.23） | `compose.yaml` |
| | nginx | 1.30.6（alpine3.24、stable 系） | `compose.yaml` |
| | Node.js | 24.22.2（alpine3.24、LTS） | `compose.yaml` / CI |
| バックエンド | Laravel Framework | 13.39.0 | `backend/composer.lock` |
| | Laravel Sanctum | 4.3.3 | 同上 |
| | Pest / PHPUnit | 4.7.8 / 12.5.33 | 同上 |
| | Larastan（PHPStan レベル 8） | 3.14.0 | 同上 |
| | Laravel Pint | 1.32.1 | 同上 |
| フロントエンド | React / React DOM | 19.3.1 | `frontend/package-lock.json` |
| | Vite / @vitejs/plugin-react | 8.3.5 / 6.2.1 | 同上 |
| | TypeScript | 6.0.3 | 同上 |
| | Tailwind CSS | 4.3.4 | 同上 |
| | ESLint / typescript-eslint | 10.14.0 / 8.72.1 | 同上 |
| | Vitest / jsdom / Testing Library | 5.1.0 / 30.1.3 / 16.3.3 | 同上 |
| CI | actions/checkout | v7.0.1（SHA 固定） | `.github/workflows/ci.yml` |
| | gitleaks | 8.30.1（digest 固定） | 同上 |
| | Trivy | 0.76.1（digest 固定） | 同上 |

選定上の注意：

- **TypeScript 6.0 系**：typescript-eslint が TypeScript 6.1 未満のみ対応のため、Vite テンプレート既定の 7.0 ではなく 6.0 を採用。
- **ESLint**：Vite テンプレート既定の oxlint ではなく、要件どおり ESLint を採用。XSS 対策として `dangerouslySetInnerHTML`・`innerHTML` 等を `no-restricted-syntax` でエラー化。
- **minimatch**：ESLint 系の開発依存に含まれる脆弱性（GHSA-g3hv-75wg-m249）のため `overrides` で 11.0.4 以上に固定。
- **Redis 8**：Redis 8 は AGPLv3 / RSALv2 / SSPLv1 のトリプルライセンス。本プロジェクトでは改変せず内部のキャッシュ・キューとして利用。

## 前提環境

- Windows 11 + **WSL2（Ubuntu）**
- **Docker Desktop（WSL2 連携を有効化）**：Settings → Resources → WSL integration で Ubuntu を有効にする
- Git（WSL 内）、`openssl`（`.env` の秘密値生成に使用）

> PHP・Composer・Node.js をホスト（Windows / WSL）にインストールする必要はありません。すべてコンテナ内で実行します。
> リポジトリは **WSL2 の Linux ファイルシステム内**（例：`~/projects/`）に置いてください。`/mnt/c` 配下では bind mount が非常に遅く、ファイル権限も正しく扱えません。

## セットアップ

WSL（Ubuntu）のシェルで実行します。

```bash
# 1. 取得（WSL の Linux ファイルシステム内に置く）
git clone https://github.com/TakahiroNago/secureflow-ai.git ~/projects/secureflow-ai
cd ~/projects/secureflow-ai

# 2. .env を生成（秘密値はローカルでランダム生成され、表示されない。既存の .env は上書きしない）
bash scripts/init-env.sh

# 3. PHP イメージをビルドし、依存関係をコンテナ内でインストール
docker compose build app
docker compose run --rm --no-deps app composer install
docker compose run --rm --no-deps frontend npm ci
docker compose run --rm --no-deps frontend npm run build   # nginx が配信する frontend/dist を作成

# 4. 起動（全サービスが healthy になるまで待機）
docker compose up -d --wait

# 5. マイグレーション（owner ロールを持つ migrate サービスでのみ実行）
docker compose run --rm migrate

# 6. 基盤の検証
bash scripts/verify-infra.sh
```

| URL | 内容 |
|---|---|
| http://localhost:8080 | nginx（ビルド済み SPA + API） |
| http://localhost:5173 | Vite 開発サーバー（ホットリロード。`/api` は nginx へプロキシ） |

公開ポートはどちらも `127.0.0.1` のみにバインドしています（既定値。`NGINX_PORT` / `FRONTEND_PORT` で変更可能）。PostgreSQL と Redis はホストに公開していません。

停止：`docker compose down`（データも削除する場合は `docker compose down -v`）

## 複数環境の同時起動

検証用クローンなどを同じマシンで同時に動かす場合は、**起動前に必ず** `.env` を変更してください。

> **変更せずに起動してはいけません。** `.env.example` の既定値（プロジェクト名 `secureflow`）のままだと、別ディレクトリのクローンでも既存環境と同じプロジェクトとして扱われ、既存のコンテナを置き換え、既存のボリュームを再利用します。DB ロールのパスワードはボリュームの初回作成時にのみ設定されるため、新しく生成したパスワードとも一致しません。

| 変数 | 既定値 | 分離されるもの |
|---|---|---|
| `COMPOSE_PROJECT_NAME` | `secureflow` | コンテナ・ネットワーク・ボリューム・PHP イメージタグ（`<プロジェクト名>-php:dev`） |
| `NGINX_PORT` | `8080` | nginx のホストポート（変更時は `APP_URL` も合わせる） |
| `FRONTEND_PORT` | `5173` | Vite 開発サーバーのホストポート |

セットアップ手順 2 の `init-env.sh` の直後に実行します（プロジェクト名とポートは任意の値に置き換えてください）。

```bash
sed -i \
  -e 's/^COMPOSE_PROJECT_NAME=.*/COMPOSE_PROJECT_NAME=secureflow-check/' \
  -e 's/^NGINX_PORT=.*/NGINX_PORT=18080/' \
  -e 's/^FRONTEND_PORT=.*/FRONTEND_PORT=15173/' \
  -e 's|^APP_URL=.*|APP_URL=http://localhost:18080|' \
  .env

# 確認：PHP イメージが <プロジェクト名>-php:dev になっていること
docker compose config --images
```

以降の手順は同じです。`scripts/verify-infra.sh` も同じ変数を参照し、その環境だけを検査します。

- `docker compose` は、その環境のディレクトリで実行してください（プロジェクトは `.env` で決まります）。
- コンテナは `restart: unless-stopped` のため、**停止せずに残すと Docker Desktop の次回起動時に再び起動します。** 検証後は `docker compose down` を実行してください。
- `docker compose down -v` は実行したディレクトリのプロジェクトのボリュームを削除します。実行前に `.env` の `COMPOSE_PROJECT_NAME` を確認してください。
- キャッシュを使わずに PHP イメージをビルドする場合：`docker compose build --no-cache --pull app`

## ヘルスチェック

| エンドポイント | 種別 | 正常 | 異常 |
|---|---|---|---|
| `GET /api/health/live` | Liveness（プロセスが応答できるか。外部依存は確認しない） | 200 `{"status":"ok"}` | — |
| `GET /api/health/ready` | Readiness（DB を app ロールで `SELECT 1`、Redis を `PING`） | 200 `{"status":"ok"}` | 503 `{"status":"unavailable"}` |

レスポンスにはバージョン・接続先・失敗した依存名・エラー詳細を含めません（詳細はアプリケーションログのみ）。レート制限は nginx で行います（60 回/分/IP）。

`app` コンテナの healthcheck は、`artisan` と `public/index.php` の存在、php-fpm の TCP 応答、`php artisan --version` の成功を確認します。`worker` / `scheduler` は、ソースの存在、`php artisan --version` の成功、`queue:work` / `schedule:work` の実プロセスを確認します。いずれも DB・Redis には接続せず、処理するジョブがないだけでは unhealthy になりません。

## データベースロールとマイグレーション

| ロール | 用途 | 認証情報を受け取るサービス |
|---|---|---|
| `postgres` | 初回起動時のロール・DB 作成のみ | `postgres` |
| `secureflow_owner` | 開発用 DB のスキーマ所有・マイグレーション（DDL）。テスト用 DB には接続不可 | `migrate` のみ |
| `secureflow_test_owner` | テスト用 DB のスキーマ所有・初期化（DDL）。開発用 DB には接続不可 | `test` のみ |
| `secureflow_app` | アプリ実行時（DML のみ、CREATE 権限なし） | `app`、`worker`、`scheduler`、`test` |

- マイグレーション：`docker compose run --rm migrate`（`php artisan migrate --database=pgsql_migrator`）
- **既存の環境を更新する場合：** `bash scripts/add-test-owner.sh` を 1 回実行します（`.env` に設定を追加し、実行中の `postgres` にロールを作成します。ボリュームは破棄せず、再実行しても安全です）。`compose.yaml` の変更により、次回の通常の `docker compose up` で `postgres` コンテナが再作成されます（データは名前付きボリュームに残ります）。
- `app` コンテナで `php artisan migrate` を実行しても権限不足で失敗します（意図した動作）。
- テーブルごとの権限は各マイグレーションで明示的に付与します（既定権限は付与しない）。
- `migrate:fresh`・`migrate:refresh`・`migrate:reset`・`db:wipe` はテスト用 DB でのみ実行できます。`migrate:rollback`・`db:seed`・`schema:dump` の手順は [database-design.md §4.5](docs/database-design.md) を参照してください。

## テストと静的解析

```bash
# バックエンド（テスト用 DB secureflow_test。スキーマは secureflow_test_owner、テストは app ロール）
docker compose run --rm test                                   # Pest
docker compose run --rm --no-deps test php vendor/bin/pint --test
docker compose run --rm --no-deps test php vendor/bin/phpstan analyse --memory-limit=1G

# フロントエンド
docker compose run --rm --no-deps frontend npm run lint
docker compose run --rm --no-deps frontend npm run typecheck
docker compose run --rm --no-deps frontend npm test
docker compose run --rm --no-deps frontend npm run build

# 基盤（ロール・ポート・Redis 認証・ヘルスチェック・SPA 配信）
bash scripts/verify-infra.sh

# 検査自体の負のテスト（一時コンテナを作成し、終了時に削除）
bash scripts/test-published-ports.sh    # 0.0.0.0・IPv6・想定外ポートの公開を検出できること
bash scripts/test-app-healthcheck.sh    # 空の bind mount 等を unhealthy と判定できること
bash scripts/test-worker-healthcheck.sh # worker / scheduler のソース・プロセス異常を判定できること
```

`test` サービスは外部に出られない内部ネットワーク上で動くため、`composer audit` / `npm audit` はネットワークに出られるコンテナで実行します：

```bash
docker compose run --rm --no-deps app composer audit
docker compose run --rm --no-deps frontend npm audit
```

## CI（GitHub Actions）

`.github/workflows/ci.yml`（push to `main` / pull request）：

| ジョブ | 内容 |
|---|---|
| secret-scan | gitleaks（Git 履歴全体）、Trivy（作業ツリーの秘密情報） |
| backend | PostgreSQL / Redis 起動、基盤検証、Pint、Larastan、Pest、composer audit |
| frontend | ESLint、型チェック、Vitest、ビルド、npm audit |
| stack | 全サービス起動、マイグレーション、`verify-infra.sh`、公開ポート検査と healthcheck の負のテスト |

ワークフローの権限は `contents: read` のみ。CI の `.env` は実行ごとに使い捨ての値を生成し、実際の AI API キーは使用しません。

## セキュリティ上の注意

- **`.env` をコミットしない**（`.gitignore` 済み）。`.env.example` にはダミー値のみを置く。
- OpenAI API キーは環境変数でのみ管理し、画面・API・ログで表示しません。Phase 2 でマスキング・出力検証とセキュリティテストが完了するまで、実際の AI API には接続しません（Phase 1 はモック AI のみ）。
- コミット前・push 前に秘密情報スキャン（gitleaks）を実施しています。
- 脆弱性を見つけた場合は Issue に詳細を書かず、リポジトリ所有者に非公開で連絡してください。

## トラブルシューティング

| 症状 | 対処 |
|---|---|
| `docker compose up` で `frontend/dist` が見つからない | セットアップ手順 3 の `npm run build` を実行する |
| `scripts/*.sh: Permission denied` | Windows 側のエディタで編集すると実行権限が外れることがある。`bash scripts/xxx.sh` で実行するか `chmod +x scripts/*.sh` |
| `.env` の値を作り直したい | `docker compose down -v` で DB ボリュームを削除してから `.env` を削除し、`scripts/init-env.sh` を再実行（DB ロールのパスワードは初回起動時にのみ設定されるため） |
| `docker` コマンドが WSL で見つからない | Docker Desktop の WSL integration で Ubuntu を有効にする |
| Docker Desktop 再起動後に nginx が終了コード 127 で停止（`error mounting ".../docker-desktop-bind-mounts/..."`、`not a directory` または `no such file or directory`）／ API が 404 `File not found.` を返す／ `Could not open input file: artisan` | Docker Desktop（WSL2）の bind mount が起動直後に解決できず、マウント先が空になった状態。`app` は `unhealthy` に、`worker` / `scheduler` は `artisan` を開けず再起動を繰り返す（`docker compose ps` で確認する）。該当サービスだけを `docker compose up -d --no-deps --force-recreate <サービス名>` で作り直す（データは名前付きボリュームに残る） |

## ライセンス

[MIT License](LICENSE)
