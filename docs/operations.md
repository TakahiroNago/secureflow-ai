# SecureFlow AI — 公開環境の運用手順

- 版：v1.1（2026-11-12）
- 状態：工程5-2（基盤の構築、§6）まで。DNS 切替前の検証（工程5-3）、公開（工程5-4）で追記する。v1.0：工程5-1
- 関連：[architecture.md §4.3](architecture.md)（公開環境のコンテナ構成）／ [security-design.md §22](security-design.md)（移行の前提条件）／ [development-roadmap.md §8](development-roadmap.md)（Phase 5 の工程）

---

## 1. 構成

| 要素 | 内容 | 決定（2026-11-12） |
|---|---|---|
| 計算資源 | AWS 東京リージョンの EC2 1 台（amd64）で、`compose.prod.yaml` のスタックを動かす。公開ポートはなく、操作は SSM Session Manager のみ | 構成 1 |
| TLS と入口 | ALB + ACM の証明書で終端し、HTTP は HTTPS へ転送する。EC2 の 80 番には ALB のセキュリティグループからのみ到達できる | 構成 1、A-1 |
| 接続元 IP | nginx が、ALB のサブネット（`TRUSTED_PROXY_CIDR`）からの接続に限って `X-Forwarded-For` を接続元とする。アプリはプロキシを信頼しない（`REMOTE_ADDR` をそのまま使う） | A-2 |
| DB と Redis | コンテナのまま（EBS、暗号化）。日次の `pg_dump` を S3 へ | 構成 2 |
| 基盤の定義 | Terraform（`infra/aws/`、§6）。apply は運用者が自分の端末で行い、状態ファイルも端末に置く。秘密情報は Terraform を通さない（`put-secrets.sh`） | 構成 3 |
| イメージ | タグ `v*` の push で `.github/workflows/release.yml` が 2 つのイメージをビルド・走査・試験し、GHCR（公開）へ push する。配備はダイジェストで固定する | 構成 4 |
| 配備 | 運用者がホストで `scripts/prod/deploy.sh <tag>` を実行する | 構成 5 |
| 秘密情報 | SSM Parameter Store（SecureString）。`scripts/prod/fetch-env.sh` が `/etc/secureflow/.env`（root のみ）に書く | 構成 6 |
| AI | `AI_PROVIDER=mock`。`openai` は A-5 の再評価を §6.1 に記すまでアプリが起動を拒否する | 構成 7 |
| ログと通知 | アプリのログは 1 行 1 JSON（`LOG_STDERR_FORMATTER`）。ホストの Docker デーモンが既定ログドライバ `awslogs` で CloudWatch Logs に送り、メトリクスフィルタとアラーム（`infra/aws/logs.tf`、`alarms.tf`）から SNS のメールへ | 構成 8、A-4 |
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

秘密でない値（次の表）は `infra/aws/parameters.tf` が String で置く。秘密（`APP_KEY`、`POSTGRES_PASSWORD`、`DB_PASSWORD`、`DB_MIGRATOR_PASSWORD`、`DB_TEST_PASSWORD`、`DB_TEST_MIGRATOR_PASSWORD`、`REDIS_PASSWORD`）は `infra/aws/put-secrets.sh` が `scripts/init-env.sh` と同じ方法で生成し（`openssl rand -hex 24`、`APP_KEY` は `base64:` + `openssl rand -base64 32`）、SecureString（鍵 `alias/secureflow-prod`）で 1 回だけ登録する。既にあるものは書き換えない。テスト用ロールのパスワードも必要である（postgres の初期化スクリプトが空を拒否する）。

| 変数 | 値 |
|---|---|
| `APP_ENV` | `production` |
| `APP_URL` | `https://secureflow.art-full-stack.com` |
| `PUBLIC_HOST` | `secureflow.art-full-stack.com`（`SANCTUM_STATEFUL_DOMAINS` になる。ポートなし） |
| `TRUSTED_PROXY_CIDR` | VPC の CIDR（`10.0.0.0/16`）。ALB の送信元はこの中にあり、80 番に届くのは ALB のセキュリティグループだけ |
| `NGINX_BIND` / `NGINX_PORT` | `0.0.0.0` / `80`（ALB のターゲット。到達はセキュリティグループで ALB に限る） |
| `COMPOSE_PROJECT_NAME` | `secureflow-prod` |
| `BACKUP_BUCKET` | `secureflow-prod-backups-<アカウント ID>`（出力 `backup_bucket`） |
| `AI_PROVIDER` | `mock` |
| `LOG_LEVEL`、`DB_DATABASE`、`DB_TEST_DATABASE`、`DB_USERNAME`、`DB_MIGRATOR_USERNAME`、`DB_TEST_USERNAME`、`DB_TEST_MIGRATOR_USERNAME` | `.env.example` と同じ値 |

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

順に、Parameter Store から `.env` を書き直し、リポジトリをタグに合わせ、イメージをタグで pull してダイジェストを固定し、バックアップ（`--label pre-deploy`）、`postgres`・`redis` の起動、`migrate`、サービスの入れ替え（`up -d --wait --remove-orphans`）、`scripts/prod/check.sh` を実行する。どの段階で失敗しても次へ進まず、マイグレーションが成功するまでサービスは入れ替えない。最後に `scripts/prod/systemd/` のタイマー（バックアップ、監査アンカー）を `/etc/systemd/system` に置いて有効にする（配備のたびに同じ版に揃う）。

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

読み取りのみ：コンテナの health と配備したダイジェスト、nginx 経由の liveness・readiness と HSTS、公開ポートが nginx の 80 番だけであること、`audit:status` と `audit:verify --all`、scheduler の一覧と worker のキュー、ホストのログドライバが `awslogs` でタイマーが有効でデータ用ボリュームが `/var/lib/docker` にあること（PROD-C6）。`scripts/verify-infra.sh` は owner で CREATE/DROP を行うため公開環境では使わない。

### 4.5 バックアップと復元

- 日次：`secureflow-backup.timer`（`scripts/prod/systemd/`）が `backup.sh --label daily` を実行する。`pg_dump -Fc` を `/var/backups/secureflow` に書き、SHA-256 を添えて `s3://<BACKUP_BUCKET>/dumps/` へ上げる。失敗はメトリクス `SecureFlow/BackupFailed`。
- 復元試験（工程5-3 で実施し、以後はスクリプトを変えたとき）：`sudo bash scripts/prod/restore.sh <dump> [--from-s3 dumps/<name>]` は作業用 DB `secureflow_restore_test` に owner ロールで復元し（`--role`、`--no-owner`）、その DB で `audit:verify --all` を実行する。終わったら作業用 DB を削除する。
- 本番 DB への復元は別の判断である：`app`・`worker`・`scheduler` を止め、本番 DB を自分で削除してから `--into <本番 DB 名>` で復元し、サービスを起動する。スクリプトはこの状態でなければ拒否する。
- ダンプは秘密として扱う（パスワードのハッシュと監査チェーンを含む。R-21）。バケットはバージョニングと KMS の暗号化を有効にし、インスタンスロールには put・get・list のみを許す（`infra/aws/s3.tf`、`iam.tf`。削除は誰にも許していない）。

### 4.6 監査ログのアンカー

`secureflow-audit-anchor.timer` が日次に `audit-anchor.sh` を実行する。S3 の最新のヘッドを `--anchor` に `audit:verify --all` を実行し（終了コード ≠ 0 でメトリクス `AuditVerifyFailed=1`）、`audit:head --all` を `s3://<BACKUP_BUCKET>/audit-heads/<時刻>.jsonl` に保管する（失敗で `AuditAnchorFailed=1`）。DB の所有者が保管したヘッドを消せないよう、ホストのロールに削除の権限を与えない（上書きは新しい版になり、前の版が残る）。

### 4.7 アラート（`infra/aws/alarms.tf`）

| アラーム（`secureflow-prod-` に続く） | 信号 | 条件 | 重要度 |
|---|---|---|---|
| `AuditUnavailable` | ログ：`audit.unavailable` の `value` が 1 または `unknown` | 1 件 | 最高 |
| `AuditGauge` | ログ：`audit.unavailable` の行そのもの（`audit:housekeeping` が毎分書く） | 5 分間に 1 件もない（データなしも発報：scheduler、アプリ、ログの経路のどれかが止まっている） | 最高 |
| `DbSuspected` | ログ：`storage_scope=db_suspected` | 1 件 | 最高（コンテナを再起動しない） |
| `OutageStarted` | ログ：`*.outage_started`（audit、db、readiness の依存先） | 1 件 | 高 |
| `RecordingFailed` | ログ：`audit.write_failed`、`*_unrecorded`、`*_not_recorded`、抑制の合計、`audit.verification_failed`、`security.canary_leak` など | 1 件 | 高 |
| `LogCritical` ／ `LogError` | ログ：CRITICAL 以上の行 ／ ERROR の行 | 1 件 ／ 5 分に 5 件 | 高 ／ 中 |
| `AuditVerifyFailed`、`AuditAnchorFailed`、`BackupFailed` | ホストのスクリプトのメトリクス（名前空間 `SecureFlow`） | 1 日の最大が 1 以上、またはデータなし（タイマーが止まると約 2 日で発報） | 高 |
| `AlbUnhealthyHost` | ALB の UnHealthyHostCount | 1 以上が 2 分 | 高（liveness が 504 のときはワーカーの枯渇を疑う。A-3） |
| `AlbTarget5xx` ／ `AlbElb5xx` | ALB の HTTPCode_Target_5XX_Count ／ HTTPCode_ELB_5XX_Count | 5 分に 10 件 | 中 |
| `DiskRoot` ／ `DiskData` | CloudWatch エージェントの `disk_used_percent`（`/` ／ `/var/lib/docker`） | 80% 以上 | 中（WAL の枯渇の前に気づく。R-18） |
| `Memory` | `mem_used_percent` | 90% 以上が 10 分 | 中 |
| `InstanceStatusCheck` | EC2 StatusCheckFailed | 1 以上が 2 分 | 高 |

すべて SNS トピック `secureflow-prod-alerts` からメールへ（復旧も通知する。購読は確認メールで確定する）。予算は AWS Budgets が直接メールする（月額の 80%、予測が 100% を超えたとき）。ログのフィルタのパターンと試料の行は `infra/aws/metric-filters.json` にあり、`scripts/check-metric-filters.py`（CI）がコードと、`infra/aws/test-metric-filters.sh`（運用者）が CloudWatch の構文解析器と照合する。アプリのログは 1 行 1 JSON（`LOG_STDERR_FORMATTER`、[architecture.md §4.3](architecture.md)）で、機密情報の除去を経ている（[security-design.md §17](security-design.md)）。保持は 90 日。

## 5. 工程5-3 で実施して記録する項目

- A-2：別の 2 つの接続元から、ログインの IP 単位の制限が利用者ごとに効き、`audit_logs.ip_address` が実際の IP になることを確認する。
- A-3：ホスト上で DB を実際に凍結し（`docker pause`）、`request_terminate_timeout` でワーカーが戻ること、`app` の healthcheck が unhealthy になること、ALB が unhealthy と判定しアラームが出ることを確認する。
- B：`pg_dump` の復元試験、負荷の再測定（`scripts/test-audit-load.py`）、レート制限の暫定値の見直し。
- アラートの実発報：`audit:verify` の失敗を模擬し、メールが届くことを確認する。scheduler を 5 分止めて `AuditGauge` が発報し、再開で OK が届くことも確認する（メールの到達そのものは §6.2 の 6 で確認済みとする）。

## 6. 基盤の構築（工程5-2、`infra/aws/`）

### 6.1 前提（運用者の端末）

- AWS アカウント、管理者権限の IAM ユーザーとその CLI プロファイル（`aws configure --profile terraform`）、AWS CLI v2、Terraform 1.10 以上（CI は 1.17.1）、Session Manager プラグイン。
- `put-secrets.sh` と `test-metric-filters.sh` は bash、python（3.x）、AWS CLI、openssl が要る。Windows では Git Bash から実行できる（`python` と `aws` が PATH にあればよい。引数のパス変換と `file://` の扱いはスクリプトが吸収する）。WSL から実行するなら WSL 側にも AWS CLI とプロファイルが要る。リージョンは両スクリプトの `--region`（既定 `ap-northeast-1`）で渡す（プロファイルに `region` がなくてもよい）。
- ドメインの DNS（Cloudflare）に CNAME を追加できること。レコードは「DNS only」（プロキシなし）にする：プロキシを通すと接続元が Cloudflare になり、A-2 の前提が崩れる。
- 資格情報はリポジトリにも CI にも置かない。状態ファイル（`infra/aws/*.tfstate`）と `terraform.tfvars` は gitignore 済み。状態ファイルには資源の識別子と `alert_email` が入り、秘密情報は入らない（`put-secrets.sh` が Terraform を通さずに登録する）。状態ファイルは端末の外に出さない。

### 6.2 手順

```bash
cd infra/aws
cp terraform.tfvars.example terraform.tfvars      # aws_profile、public_host、alert_email を書く。enable_https = false のまま
terraform init
bash test-metric-filters.sh --profile terraform   # フィルタのパターンを CloudWatch の構文解析器で検査する（資源は作らない）
terraform plan
terraform apply                                   # 1 回目：証明書は検証待ちで、HTTPS リスナーはまだない
bash put-secrets.sh --profile terraform           # 秘密情報を生成して Parameter Store へ（1 回だけ。既にあるものは触らない）
terraform output acm_validation_records           # この CNAME を Cloudflare に追加する（DNS only）
```

1. 検証用の CNAME を追加したら、`terraform.tfvars` の `enable_https` を `true` にして `terraform apply`。ACM の発行を待ち（通常は数分、最長 60 分）、HTTPS リスナーと公開ホスト名のルールができる。
2. SNS からの確認メール（`alert_email` 宛）のリンクを開いて購読を確定する。確定するまでアラームは届かない。
3. ホストの初回起動を確認する：`aws ssm start-session --target $(terraform output -raw instance_id) --profile terraform` で入り、`sudo tail /var/log/secureflow-first-boot.log` の末尾が `secureflow first boot done`、`docker info --format '{{.LoggingDriver}}'` が `awslogs`、`findmnt /var/lib/docker` がデータ用ボリュームであること。
4. リリースと初回の配備（4.1、4.2）。`deploy.sh` が `.env` を書き、タイマーを有効にする。`check.sh` が PROD-C1〜C6 に合格すること。
5. DNS を切り替える前に ALB 経由で確認する（`--resolve` で公開ホスト名を ALB の IP に向ける）：

```bash
alb=$(terraform output -raw alb_dns_name); ip=$(dig +short "$alb" | head -1); host=$(terraform output -json public_dns_record | python3 -c 'import json, sys; print(json.load(sys.stdin)["name"])')
curl -sI --resolve "$host:443:$ip" "https://$host/api/health/live"       # 200、Strict-Transport-Security
curl -sI --resolve "$host:80:$ip" "http://$host/"                        # 301 → https
curl -sk -o /dev/null -w '%{http_code}\n' "https://$alb/"                # 421（ALB 自身の名前では応答しない）
```

6. メールの到達：`aws cloudwatch set-alarm-state --alarm-name secureflow-prod-AuditVerifyFailed --state-value ALARM --state-reason test --profile terraform` で ALARM と、その後の OK のメールが届くこと。実際の失敗での発報は工程5-3（§5）。
7. 公開（工程5-4）：`terraform output public_dns_record` の CNAME を Cloudflare に追加する（DNS only）。

### 6.3 作るもの

| 資源 | 内容 |
|---|---|
| VPC `10.0.0.0/16` | パブリックサブネット 2 つ（ALB は 2 AZ）。NAT ゲートウェイと VPC エンドポイントは置かない |
| セキュリティグループ | ALB：443 と 80 を全体から受け、EC2 の 80 番にのみ送る。EC2：ALB からの 80 番のみ受け、送信は 443・80（AWS API、イメージ、パッケージ）と VPC 内の DNS のみ |
| EC2 | Ubuntu 24.04（SSM の公開パラメータから。その後の変化は無視する）、`t3.small`、IMDSv2 のみでホップ数 1（コンテナからインスタンスの資格情報に届かない）、ルート 16 GB、データ用 20 GB（`/var/lib/docker`。`prevent_destroy`）、SSH なし |
| 初回起動（`user-data.sh.tftpl`） | データ用ボリュームの初期化と mount、Docker（既定ログドライバ `awslogs`、non-blocking）、AWS CLI、CloudWatch エージェント（ディスク、メモリ）、時刻同期、リポジトリの clone。タイマーは `deploy.sh` が有効にする |
| ALB + ACM | TLS 1.2/1.3、HTTP は 301、公開ホスト名以外は 421、`/api/health/live` を 30 秒ごと（異常 3 回）、`drop_invalid_header_fields` |
| S3 | バージョニング、KMS、公開遮断、TLS のみ。`dumps/` は 35 日で削除、`audit-heads/` の現行版は残す。ホストのロールは put・get・list のみで削除できない |
| KMS | 1 つの鍵（S3、Parameter Store の SecureString、ロググループ、SNS）。ローテーションあり |
| IAM | ホストのロール：Session Manager、`/secureflow/prod` の読み取り、鍵の利用は SSM と S3 を経由したときのみ、ロググループへの書き込み、メトリクスは `SecureFlow` と `CWAgent` のみ。`AmazonSSMManagedInstanceCore` は使わない（全パラメータの読み取りを含むため） |
| Parameter Store | 秘密でない値を Terraform が String で置く（3.1）。秘密は `put-secrets.sh` |
| CloudWatch | ロググループ（90 日、KMS）、フィルタ 7 つ、アラーム 17（4.7）、SNS トピック（KMS、メール購読） |
| Budgets | 月 60 ドル。80% と予測 100% でメール |

### 6.4 費用の目安（東京、月額）

EC2 t3.small 約 20 ドル、ALB 約 20 ドル、パブリック IPv4（EC2 1 つと ALB 2 つ）約 11 ドル、EBS 36 GB 約 4 ドル、KMS 1 ドル、S3・CloudWatch・Parameter Store は少額。合計 55〜60 ドル。予算の 80% の通知は毎月届く見込みである。

### 6.5 変更と破棄

- `instance_type` の変更はその場で行われる（停止と起動を伴う）。AMI と初回起動スクリプトの変更は無視される：反映するにはバックアップの後に `terraform apply -replace=aws_instance.host`。データ用ボリュームは残り、新しいインスタンスに再接続される（`fstab` はラベル指定）。
- `terraform destroy` はバケットとデータ用ボリュームの `prevent_destroy` と ALB の削除保護で止まる。全部を消すときは、それらを外してから行う。
- 秘密情報の交換は `put-secrets.sh` では行わない（既にあるものは触らない）。DB のパスワードは DB 側を先に変え、`aws ssm put-parameter --overwrite` で合わせる。
