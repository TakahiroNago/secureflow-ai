# SecureFlow AI — 公開環境の運用手順

- 版：v1.0（2026-11-12）
- 状態：工程5-1（本番用イメージ・Compose・スクリプト）の範囲。基盤の構築（Terraform、工程5-2）、DNS 切替前の検証（工程5-3）、公開（工程5-4）で追記する
- 関連：[architecture.md §4.3](architecture.md)（公開環境のコンテナ構成）／ [security-design.md §22](security-design.md)（移行の前提条件）／ [development-roadmap.md §8](development-roadmap.md)（Phase 5 の工程）

---

## 1. 構成

| 要素 | 内容 | 決定（2026-11-12） |
|---|---|---|
| 計算資源 | AWS 東京リージョンの EC2 1 台（amd64）で、`compose.prod.yaml` のスタックを動かす。公開ポートはなく、操作は SSM Session Manager のみ | 構成 1 |
| TLS と入口 | ALB + ACM の証明書で終端し、HTTP は HTTPS へ転送する。EC2 の 80 番には ALB のセキュリティグループからのみ到達できる | 構成 1、A-1 |
| 接続元 IP | nginx が、ALB のサブネット（`TRUSTED_PROXY_CIDR`）からの接続に限って `X-Forwarded-For` を接続元とする。アプリはプロキシを信頼しない（`REMOTE_ADDR` をそのまま使う） | A-2 |
| DB と Redis | コンテナのまま（EBS、暗号化）。日次の `pg_dump` を S3 へ | 構成 2 |
| 基盤の定義 | Terraform（`infra/aws/`、工程5-2）。apply は運用者が自分の端末で行う | 構成 3 |
| イメージ | タグ `v*` の push で `.github/workflows/release.yml` が 2 つのイメージをビルド・走査・試験し、GHCR（公開）へ push する。配備はダイジェストで固定する | 構成 4 |
| 配備 | 運用者がホストで `scripts/prod/deploy.sh <tag>` を実行する | 構成 5 |
| 秘密情報 | SSM Parameter Store（SecureString）。`scripts/prod/fetch-env.sh` が `/etc/secureflow/.env`（root のみ）に書く | 構成 6 |
| AI | `AI_PROVIDER=mock`。`openai` は A-5 の再評価を §6.1 に記すまでアプリが起動を拒否する | 構成 7 |
| ログと通知 | Docker デーモンの既定ログドライバを `awslogs` にし（工程5-2）、CloudWatch Logs のメトリクスフィルタとアラームから SNS のメールへ | 構成 8、A-4 |
| ワーカーの枯渇 | php-fpm の `request_terminate_timeout=30s`、`app` の healthcheck が空きワーカーを確認、ALB は `/api/health/live` を監視。unhealthy で自動再起動しない | 構成 9、A-3 |
| 監査アンカー | 日次に `audit:head` を S3 へ保管し、前回のヘッドで `audit:verify --anchor` を実行する | 構成 10、A-4 |

## 2. イメージ

| イメージ | 作り方 | 中身 |
|---|---|---|
| `ghcr.io/takahironago/secureflow-ai/php:<tag>` | `docker/php/Dockerfile` の `prod` ターゲット | `backend/` を COPY し、`composer install --no-dev`。PCOV なし。`opcache.validate_timestamps=0`。起動時に `secureflow-entrypoint` が環境変数から `config:cache`・`route:cache`・`event:cache` を作ってから本来のコマンドを実行する。healthcheck は `secureflow-healthcheck`（`docker/php/healthcheck-prod.sh`） |
| `ghcr.io/takahironago/secureflow-ai/web:<tag>` | `docker/nginx/Dockerfile` | node の段階で `npm ci` と `npm run build`、nginx の段階に `dist/`、`default.conf`、snippets（`security-headers.conf` は HSTS 付きの本番版 `docker/nginx/prod/`）、`TRUSTED_PROXY_CIDR` から起動時に描画する `real_ip` の設定 |

`.dockerignore` が `vendor`、`node_modules`、`tests`、`.env*`、`docs`、`scripts` をビルドコンテキストから外す。イメージに `.env` や鍵は入らない（`scripts/test-prod-stack.sh` PROD-01）。

## 3. ホストの配置

| 場所 | 内容 |
|---|---|
| `/opt/secureflow` | リポジトリ。配備したタグをチェックアウトした状態（`compose.prod.yaml` と `scripts/prod/` を使う） |
| `/etc/secureflow/.env` | 環境変数（`fetch-env.sh` が Parameter Store から書く。root のみ、600） |
| `/etc/secureflow/images.env` | `SECUREFLOW_PHP_IMAGE` / `SECUREFLOW_WEB_IMAGE`（ダイジェスト固定。`deploy.sh` が書く） |
| `/etc/secureflow/deployed`、`deployed.previous` | 配備したタグとダイジェスト。`.previous` は戻し先 |
| `/var/backups/secureflow` | 直近 3 世代のダンプ（S3 にも保管） |

Compose の呼び出しは常に次の形である（`scripts/prod/lib.sh` の `compose`）。

```bash
docker compose --project-directory /opt/secureflow \
  --env-file /etc/secureflow/.env --env-file /etc/secureflow/images.env \
  -f /opt/secureflow/compose.prod.yaml <command>
```

### 3.1 Parameter Store の変数（`/secureflow/prod/<NAME>`）

`.env.example` の変数に加えて次を置く。値は `scripts/init-env.sh` と同じ方法で運用者が生成する（`openssl rand -hex 24`、`APP_KEY` は `base64:` + `openssl rand -base64 32`）。

| 変数 | 値 |
|---|---|
| `APP_ENV` | `production` |
| `APP_URL` | `https://secureflow.art-full-stack.com` |
| `PUBLIC_HOST` | `secureflow.art-full-stack.com`（`SANCTUM_STATEFUL_DOMAINS` になる。ポートなし） |
| `TRUSTED_PROXY_CIDR` | ALB のサブネットの CIDR（VPC の CIDR で可。工程5-2 の出力） |
| `NGINX_BIND` / `NGINX_PORT` | `0.0.0.0` / `80`（ALB のターゲット。到達はセキュリティグループで ALB に限る） |
| `COMPOSE_PROJECT_NAME` | `secureflow-prod` |
| `BACKUP_BUCKET` | ダンプと監査ヘッドの S3 バケット名（工程5-2 の出力） |
| `AI_PROVIDER` | `mock` |

`DB_MIGRATOR_*` は `postgres`（初回のロール作成）と `migrate` にのみ渡る。`app`・`worker`・`scheduler` には渡らない（`compose.prod.yaml`、`scripts/test-prod-stack.sh` PROD-06）。

## 4. 手順

### 4.1 リリース

1. main の CI が全ジョブ成功であることを確認する。
2. タグを付けて push する：`git tag v1.0.0 && git push origin v1.0.0`（署名の扱いは開発環境と同じ）。
3. `Release` ワークフローの成功を待つ。ジョブサマリに 2 つのイメージのダイジェストが出る。
4. ホストで配備する（4.2）。

### 4.2 配備

```bash
sudo bash /opt/secureflow/scripts/prod/deploy.sh v1.0.0
```

順に、Parameter Store から `.env` を書き直し、リポジトリをタグに合わせ、イメージをタグで pull してダイジェストを固定し、バックアップ（`--label pre-deploy`）、`postgres`・`redis` の起動、`migrate`、サービスの入れ替え（`up -d --wait --remove-orphans`）、`scripts/prod/check.sh` を実行する。どの段階で失敗しても次へ進まず、マイグレーションが成功するまでサービスは入れ替えない。

初回は `deployed` がないためバックアップを飛ばす。初回の後に組織と管理者を作る（`db:seed` は本番相当の環境では実行できない。[database-design.md §4.5](database-design.md)）：

```bash
cd /opt/secureflow
alias prod='sudo docker compose --env-file /etc/secureflow/.env --env-file /etc/secureflow/images.env -f compose.prod.yaml'
prod exec app php artisan organization:create --name='<組織名>'      # 初回のみ：組織と既定の設定（ユーザーは作らない）
prod exec app php artisan user:create --organization='<組織名>' --name='...' --email=... --role=admin   # パスワードは対話入力
```

admin は 2 名以上置く（[security-design.md §22 B](security-design.md)、R-08）。

### 4.3 戻し

```bash
sudo bash /opt/secureflow/scripts/prod/deploy.sh --rollback
```

`deployed.previous` のタグとダイジェストに戻す。DB には触れない：マイグレーションは前進のみで、戻す必要があるときは 4.5 の復元を別に判断する。

### 4.4 確認

```bash
sudo bash /opt/secureflow/scripts/prod/check.sh
```

読み取りのみ：コンテナの health と配備したダイジェスト、nginx 経由の liveness・readiness と HSTS、公開ポートが nginx の 80 番だけであること、`audit:status` と `audit:verify --all`、scheduler の一覧と worker のキュー。`scripts/verify-infra.sh` は owner で CREATE/DROP を行うため公開環境では使わない。

### 4.5 バックアップと復元

- 日次：`secureflow-backup.timer`（`scripts/prod/systemd/`）が `backup.sh --label daily` を実行する。`pg_dump -Fc` を `/var/backups/secureflow` に書き、SHA-256 を添えて `s3://<BACKUP_BUCKET>/dumps/` へ上げる。失敗はメトリクス `SecureFlow/BackupFailed`。
- 復元試験（工程5-3 で実施し、以後はスクリプトを変えたとき）：`sudo bash scripts/prod/restore.sh <dump> [--from-s3 dumps/<name>]` は作業用 DB `secureflow_restore_test` に owner ロールで復元し（`--role`、`--no-owner`）、その DB で `audit:verify --all` を実行する。終わったら作業用 DB を削除する。
- 本番 DB への復元は別の判断である：`app`・`worker`・`scheduler` を止め、本番 DB を自分で削除してから `--into <本番 DB 名>` で復元し、サービスを起動する。スクリプトはこの状態でなければ拒否する。
- ダンプは秘密として扱う（パスワードのハッシュと監査チェーンを含む。R-21）。バケットはバージョニングと暗号化を有効にし、インスタンスロールには put と get のみを許す（工程5-2）。

### 4.6 監査ログのアンカー

`secureflow-audit-anchor.timer` が日次に `audit-anchor.sh` を実行する。S3 の最新のヘッドを `--anchor` に `audit:verify --all` を実行し（終了コード ≠ 0 でメトリクス `AuditVerifyFailed=1`）、`audit:head --all` を `s3://<BACKUP_BUCKET>/audit-heads/<時刻>.jsonl` に保管する（失敗で `AuditAnchorFailed=1`）。DB の所有者が保管したヘッドを書き換えられないよう、ホストのロールに削除と上書きの権限を与えない。

### 4.7 アラート（工程5-2 で作成）

| 信号 | 条件 | 重要度 |
|---|---|---|
| `metric=audit.unavailable value=1` または `audit.outage_started` | ログのメトリクスフィルタ、1 件で発報 | 最高 |
| `storage_scope=db_suspected` | 同上 | 最高（コンテナを再起動しない） |
| `audit.events_suppressed`、`login_failed_unrecorded` などの記録の失敗 | 同上 | 高 |
| `SecureFlow/AuditVerifyFailed`、`AuditAnchorFailed`、`BackupFailed` | 1 以上、またはデータなし（タイマーが動いていない） | 高 |
| ALB の UnHealthyHostCount | 1 以上が 2 期間 | 高（liveness が 504 のときはワーカーの枯渇を疑う。A-3） |
| ALB の HTTPCode_Target_5XX_Count | 連続 | 中 |
| EBS の使用率 | 80% 以上 | 中（WAL の枯渇の前に気づく。R-18） |
| EC2 StatusCheckFailed | 1 以上 | 高 |

ログは機密情報の除去を経ている（[security-design.md §17](security-design.md)）。保持は 90 日。

## 5. 工程5-3 で実施して記録する項目

- A-2：別の 2 つの接続元から、ログインの IP 単位の制限が利用者ごとに効き、`audit_logs.ip_address` が実際の IP になることを確認する。
- A-3：ホスト上で DB を実際に凍結し（`docker pause`）、`request_terminate_timeout` でワーカーが戻ること、`app` の healthcheck が unhealthy になること、ALB が unhealthy と判定しアラームが出ることを確認する。
- B：`pg_dump` の復元試験、負荷の再測定（`scripts/test-audit-load.py`）、レート制限の暫定値の見直し。
- アラートの実発報：`audit:verify` の失敗を模擬し、メールが届くことを確認する。
