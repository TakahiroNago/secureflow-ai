# infra/aws — 公開環境の基盤（Terraform）

公開環境（AWS 東京リージョン）の定義です。構成の判断は [docs/architecture.md §14](../../docs/architecture.md) の D33〜D36、手順は [docs/operations.md §6](../../docs/operations.md) にあります。apply は運用者が自分の端末で行い、状態ファイル（`*.tfstate`）と `terraform.tfvars` はリポジトリに入れません。CI は `terraform fmt` と `validate`、Trivy の設定走査のみを行い、AWS の資格情報を持ちません。

| ファイル | 内容 |
|---|---|
| `versions.tf` / `variables.tf` / `main.tf` / `outputs.tf` | プロバイダ、入力、共通の名前、出力（DNS に追加するレコードなど） |
| `network.tf` / `security-groups.tf` | VPC、パブリックサブネット 2 つ、ALB → EC2 の 80 番のみ、EC2 の送信は 80/443 と DNS のみ |
| `kms.tf` / `s3.tf` / `iam.tf` | 鍵、ダンプと監査ヘッドのバケット（バージョニング、削除権限なし）、ホストのロール |
| `ec2.tf` / `user-data.sh.tftpl` | EC2（SSM のみ、IMDSv2、データ用ボリューム）と初回起動の処理 |
| `alb.tf` | ALB、ACM 証明書（DNS 検証）、HTTP→HTTPS、公開ホスト名以外は 421 |
| `parameters.tf` | Parameter Store の秘密でない値。秘密は `put-secrets.sh` が 1 回だけ登録する |
| `logs.tf` / `metric-filters.json` / `alarms.tf` / `budget.tf` | ログ、メトリクスフィルタ、アラーム、SNS、予算 |
| `test-metric-filters.sh` | フィルタのパターンを CloudWatch の構文解析器で検査する（資源を作らない） |
| `terraform.tfvars.example` | `terraform.tfvars` の雛形 |
