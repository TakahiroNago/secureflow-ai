<?php

namespace App\Security\Scanning;

enum ScanDecision: string
{
    case Allow = 'allow';
    case Warn = 'warn';
    case Block = 'block';
}
