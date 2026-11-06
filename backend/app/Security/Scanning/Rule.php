<?php

namespace App\Security\Scanning;

/**
 * docs/security-design.md §3.3. Severity is for showing and action is for the flow: neither comes from the other.
 */
enum Rule: string
{
    case Email = 'PII-EMAIL';
    case Phone = 'PII-PHONE-JP';
    case Card = 'PII-CARD';
    case MyNumber = 'PII-MYNUMBER';
    case ApiKey = 'SEC-APIKEY';
    case Token = 'SEC-TOKEN';
    case Password = 'SEC-PASSWORD';
    case PrivateKey = 'SEC-PRIVKEY';
    case Entropy = 'SEC-ENTROPY';
    case MaskFailed = 'MASK-FAIL';

    public function category(): string
    {
        return match ($this) {
            self::Email, self::Phone, self::Card, self::MyNumber => 'pii',
            self::MaskFailed => 'masking',
            default => 'secret',
        };
    }

    public function severity(): Severity
    {
        return match ($this) {
            self::Email, self::Phone, self::Entropy => Severity::Medium,
            self::Card, self::MyNumber, self::Password, self::MaskFailed => Severity::High,
            self::ApiKey, self::Token, self::PrivateKey => Severity::Critical,
        };
    }

    public function action(): ScanAction
    {
        return match ($this) {
            self::Email, self::Phone, self::Card, self::MyNumber => ScanAction::MaskContinue,
            self::Entropy => ScanAction::Warn,
            default => ScanAction::Block,
        };
    }

    public function replacement(): string
    {
        return match ($this) {
            self::Email => '[EMAIL_REDACTED]',
            self::Phone => '[PHONE_REDACTED]',
            self::Card => '[CREDIT_CARD_REDACTED]',
            self::MyNumber => '[MY_NUMBER_REDACTED]',
            self::ApiKey => '[API_KEY_REDACTED]',
            self::Token => '[TOKEN_REDACTED]',
            self::Password => '[PASSWORD_REDACTED]',
            self::PrivateKey => '[PRIVATE_KEY_REDACTED]',
            self::Entropy => '[SECRET_REDACTED]',
            self::MaskFailed => '[REDACTED]',
        };
    }

    /**
     * A fixed sentence: it never carries any of the text.
     */
    public function message(): string
    {
        return match ($this) {
            self::Email => 'メールアドレスを検出しマスキングしました',
            self::Phone => '電話番号を検出しマスキングしました',
            self::Card => 'クレジットカード番号形式の文字列を検出しマスキングしました',
            self::MyNumber => 'マイナンバー形式の文字列を検出しマスキングしました',
            self::ApiKey => 'APIキー形式の文字列を検出しました',
            self::Token => 'アクセストークン形式の文字列を検出しました',
            self::Password => 'パスワードと思われる文字列を検出しました',
            self::PrivateKey => '秘密鍵を検出しました',
            self::Entropy => '秘密情報の疑いがある文字列を検出しマスキングしました',
            self::MaskFailed => 'マスキングを完了できなかったため処理を停止しました',
        };
    }
}
