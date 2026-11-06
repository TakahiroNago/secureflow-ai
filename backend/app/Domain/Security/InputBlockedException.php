<?php

namespace App\Domain\Security;

use App\Security\Scanning\InputScanResult;
use RuntimeException;

/**
 * The scan stopped the work, and its record has committed. A blocked result holds none of the text.
 */
final class InputBlockedException extends RuntimeException
{
    public function __construct(public readonly InputScanResult $result)
    {
        parent::__construct('Input blocked');
    }

    /**
     * A fixed sentence for each reason.
     */
    public function detail(): string
    {
        return match ($this->result->blockReason) {
            InputScanResult::REASON_SECRET => '認証情報・秘密情報と思われる文字列が含まれているため処理を停止しました。該当箇所を削除して再度入力してください。',
            InputScanResult::REASON_INJECTION => '指示の上書きなどの攻撃と思われる表現が含まれているため処理を停止しました。内容を確認して再度入力してください。',
            default => '入力を検査できなかったため処理を停止しました。内容を短くするか、しばらく待ってから再度お試しください。',
        };
    }
}
