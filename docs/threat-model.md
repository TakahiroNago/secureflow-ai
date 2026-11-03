# SecureFlow AI — 脅威モデル

- 版：v1.1（2026-11-03）
- 状態：確定（v1.1：Q-D13・Q-PII・D11・Phase 0 追加条件を反映）
- 手法：STRIDE ＋ OWASP Top 10 for LLM Applications 2025

---

## 1. 対象範囲

MVP（Phase 1〜3）：React SPA、Laravel API、Queue Worker、PostgreSQL、Redis、OpenAI API 連携（Phase 2〜）、ローカル Docker 環境。外部サービスへの実操作（Phase 4）、AWS（Phase 5）は対象外だが、拡張時に本モデルを更新する。

## 2. 保護資産

| ID | 資産 | 重要度 |
|---|---|---|
| A1 | ユーザーが入力する業務内容（個人情報・機密情報を含みうる） | 高 |
| A2 | 認証情報（パスワードハッシュ、セッション） | 高 |
| A3 | OpenAI APIキー | 高 |
| A4 | 承認の完全性（承認内容と実行内容の一致） | 高 |
| A5 | 監査ログの完全性 | 高 |
| A6 | 組織間・ユーザー間のデータ分離 | 高 |
| A7 | AI利用予算 | 中 |
| A8 | システムプロンプト（秘密は含めないが、攻撃の足掛かりになりうる） | 低 |

## 3. 脅威主体

| ID | 主体 | 想定 |
|---|---|---|
| U1 | 未認証の外部攻撃者 | ローカル環境でも将来の公開を想定 |
| U2 | 悪意ある、または不注意な member | 自分の権限内で攻撃入力・他人データの参照を試みる |
| U3 | 悪意ある admin | 自己承認、監査ログ改ざんを試みる |
| U4 | 間接的攻撃者 | ユーザーが貼り付けた外部文書（メール・Web）に指示を埋め込む |
| U5 | AIプロバイダ側の異常 | 不正形式・悪意あるように見える出力、障害 |
| U6 | サプライチェーン | 依存パッケージ・コンテナイメージの脆弱性 |

## 4. データフローと信頼境界

```
[U1/U2/U3 Browser] ─TB1─▶ [nginx] ─▶ [Laravel API] ─TB5─▶ [PostgreSQL]
                                         │    └──────────▶ [Redis]
       [U4 外部文書] ─(貼付)─▶ TB1        │
                                         ▼
                                     [Worker] ─TB2─▶ [OpenAI API] ─TB3─▶ [Worker]
                                         │
[Browser] ◀─TB4─ [Laravel API] ◀─────────┘
```

## 5. 脅威一覧

| ID | STRIDE / LLM | 脅威 | 主体 | 対策（[security-design.md](security-design.md)） | 検証テスト |
|---|---|---|---|---|---|
| T-01 | T / LLM01 | 直接プロンプトインジェクションでAIの指示を上書き | U2 | §3.5検出（完全ではない）、§5隔離、§7スキーマ、§8能力剥奪（最終防御） | ST-02, ST-13 |
| T-02 | T / LLM01 | 貼り付けた外部文書経由の間接インジェクション | U4 | IJ-IND、役割マーカー検出、境界文字列、能力剥奪 | ST-14 |
| T-03 | I / LLM07 | システムプロンプト・内部指示の抽出 | U2 | 秘密を含めない設計、IJ-EXF、カナリア検知 | ST-15 |
| T-04 | E / LLM06 | AIに禁止操作（メール送信・削除・シェル）を実行させる | U2/U4 | tools不使用、ActionCatalog、forbidden提出不可、ハンドラ不在 | ST-16, ST-17 |
| T-05 | E / LLM06 | AI申告の権限を水増しして承認を通す | U2/U4 | 権限はサーバー導出、permission_mismatch | ST-18 |
| T-06 | I / LLM02 | 個人情報がAIプロバイダへ送信される | U2(不注意) | §3.3マスキング（mask_continue）、送信前プレビュー、限界の明示 | ST-04 |
| T-06b | I / LLM02 | 認証・秘密情報（APIキー・トークン・パスワード・秘密鍵）がAIプロバイダへ送信・保存される | U2(不注意) | §3.3 action=block（AI未呼び出し・本文非保存）、finding の抜粋も保存しない | ST-03, ST-35 |
| T-06c | I / LLM02 | マスキング処理の失敗・すり抜けで未マスクのまま送信される | U2/U5 | §3.4 fail closed（例外・再検査残存・件数不整合で停止） | ST-36 |
| T-07 | I / LLM02 | AI出力に機密情報が含まれ保存・表示される | U5 | 出力側：個人情報はマスキング、認証・秘密情報は分析を blocked | ST-19 |
| T-08 | T / LLM05 | AI出力のスクリプトがブラウザで実行される（XSS） | U4/U5 | テキスト描画のみ、HTML描画禁止、CSP、HTML除去（補助） | ST-10, E2E-XSS |
| T-09 | T / LLM05 | 不正JSON・想定外構造で処理が誤動作 | U5 | スキーマ検証・未知キー拒否 | ST-07 |
| T-10 | T | 承認後に内容をすり替えて実行（TOCTOU） | U2 | ハッシュ紐付け、行ロック、実行時再計算 | ST-09, ST-20 |
| T-11 | E | 自己承認（admin が自分の作成したワークフローを承認） | U3 | アプリ Policy ＋ DBトリガー `approvals_forbid_self_approval` | ST-21 |
| T-11b | E | admin 以外（auditor・member）による承認 | U2 | Policy ＋ DBトリガー `approvals_require_admin` | ST-06, ST-38 |
| T-11c | E | 承認可能な admin がいない状況での承認回避・強制実行 | U2/U3 | 承認を経ない実行経路・強制実行機能を作らない、実行時再検証 | ST-37 |
| T-12 | E | 未承認タスクの実行 | U2 | 状態遷移、有効承認の計算、再検証 | ST-08 |
| T-13 | T | 同一承認での二重実行・リプレイ | U2 | UNIQUE(approval_id)、冪等性キー、部分一意インデックス | ST-22 |
| T-14 | I / E | 他ユーザー・他組織のデータ参照（IDOR） | U2 | 組織スコープ、Policy、404、UUIDに依存しない | ST-12, ST-23 |
| T-15 | E | ロール不足の操作（member が承認・監査ログ参照） | U2 | Policy、ロール別アクセス表 | ST-06 |
| T-16 | S | パスワード総当たり・クレデンシャルスタッフィング | U1 | レート制限、ロック、Argon2id | ST-11, ST-24 |
| T-17 | S | セッション固定・窃取 | U1 | ID再生成、HttpOnly/SameSite、期限 | ST-25 |
| T-18 | T | CSRF による承認・実行 | U1 | XSRF トークン、SameSite | ST-26 |
| T-19 | I | ユーザー列挙 | U1 | 同一応答・処理時間均一化 | ST-27 |
| T-20 | R / T | 監査ログの改ざん・削除・否認 | U3 | 追記専用権限、トリガー、ハッシュチェーン | ST-28 |
| T-21 | I | ログ・エラー経由の秘密情報漏洩 | U1/U2 | ログの機密情報除去、汎用エラー、APP_DEBUG=false | ST-29 |
| T-22 | I | APIキーの漏洩（コード・画面・Git） | — | 環境変数のみ、非表示、.gitignore、シークレットスキャン | CI-SECRET |
| T-23 | D / LLM10 | 大量リクエスト・高コスト入力による予算枯渇 | U2 | レート制限、トークン上限、入力長制限 | ST-11, ST-30 |
| T-24 | I | SSRF（任意URLへの通信） | U2 | ユーザー指定URL通信なし、送信先固定 | ST-31 |
| T-25 | T | SQLインジェクション | U1/U2 | Eloquent / バインド、Semgrep | ST-32, CI-SAST |
| T-26 | D | 実行中の障害で状態が Running のまま固着 | U5 | heartbeat、停滞回収、再承認必須 | ST-33 |
| T-27 | T | 依存パッケージ・イメージの脆弱性 | U6 | 最小依存、Trivy、audit | CI-SCA |
| T-28 | I / LLM09 | AIの誤った提案を鵜呑みにして承認 | U2/U3 | 提案として表示、影響・権限・リスクの明示、承認必須 | E2E |
| T-29 | E / T | アプリ実行経路からのDDL実行・権限昇格（app コンテナの侵害を含む） | U1/U6 | owner/app ロール分離、owner 認証情報は migrate コンテナのみ、app に CREATE 権限なし | P0-DB-01, P0-DB-02 |
| T-30 | I | DB・Redis への直接接続 | U1 | ホストにポートを公開しない、Redis パスワード必須 | P0-NET-01 |
| T-31 | I | 公開リポジトリへの秘密情報・個人情報・不要ファイルの混入 | — | `.gitignore`、push 前確認、CI の gitleaks（全履歴）・Trivy secret スキャン | CI-SECRET |
| T-32 | I | ヘルスチェック経由の内部情報（バージョン・接続先・エラー）漏洩 | U1 | Liveness/Readiness とも `status` のみ返却、詳細はログのみ | P0-HC-01, P0-HC-02 |

（ST-xx は [test-strategy.md §5](test-strategy.md) のセキュリティテストケース、P0-xx は同 §12 の Phase 0 基盤テスト）

## 6. OWASP Top 10 for LLM Applications 2025 対応表

| 項目 | 該当 | 対応する脅威 |
|---|---|---|
| LLM01 Prompt Injection | 該当 | T-01, T-02 |
| LLM02 Sensitive Information Disclosure | 該当 | T-06, T-07 |
| LLM03 Supply Chain | 該当 | T-27 |
| LLM04 Data and Model Poisoning | 非該当（学習・ファインチューニングなし） | — |
| LLM05 Improper Output Handling | 該当 | T-08, T-09 |
| LLM06 Excessive Agency | 該当 | T-04, T-05 |
| LLM07 System Prompt Leakage | 該当 | T-03 |
| LLM08 Vector and Embedding Weaknesses | 非該当（RAGなし） | — |
| LLM09 Misinformation | 該当 | T-28 |
| LLM10 Unbounded Consumption | 該当 | T-23 |

## 7. 残存リスク

| ID | 残存リスク | 受容理由・今後の対応 |
|---|---|---|
| R-01 | 未知・高度なプロンプトインジェクションは検出できない | 検出は補助層。AIに実行権限がなく、人間の承認が必須のため影響は「不適切な提案」に限定される |
| R-02 | 氏名・住所等の個人情報はマスキングされずAIプロバイダへ送信されうる | 画面・ドキュメントで明示。将来、固有表現抽出等を検討。プロバイダのデータ保持条件をPhase 2前に確認 |
| R-03 | DB所有者・スーパーユーザーは監査ログトリガーを無効化しチェーンを再計算できる | MVPでは検出のみ。将来、外部ストレージへのハッシュ退避 |
| R-04 | 悪意ある admin 2名の共謀による承認 | 職務分掌の限界。監査ログで事後追跡 |
| R-05 | AIの誤った提案を承認者が見落とす | MVPは模擬実行のみで実害なし。Phase 4 では操作ごとの影響表示を強化 |
| R-06 | ローカル開発環境の HTTP 運用（Secure Cookie 不可） | ローカル限定・127.0.0.1バインド。公開環境では HTTPS 必須 |
| R-07 | 検出できない形式の認証・秘密情報（独自形式のキー、分割された値等）はマスキング・停止されずに送信されうる | 検出漏れがないことは保証しない。画面・APIで明示。ルールを継続的に追加 |
| R-08 | 組織に admin が1名しかいない場合、その admin が作成したワークフローは実行できない | 職務分掌を優先した仕様として受容（D13）。運用上は admin を2名以上置く |
