<?php

namespace App\Security\Scanning;

enum ScanAction: string
{
    case Record = 'record';
    case MaskContinue = 'mask_continue';
    case Warn = 'warn';
    case Block = 'block';

    /** Which of two overlapping detections wins: the one that stops the most. */
    public function rank(): int
    {
        return match ($this) {
            self::Record => 1,
            self::MaskContinue => 2,
            self::Warn => 3,
            self::Block => 4,
        };
    }
}
