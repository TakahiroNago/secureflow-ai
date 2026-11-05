<?php

namespace App\Security\Policy;

enum PolicyDecision: string
{
    case Allowed = 'allowed';
    case Forbidden = 'forbidden';
}
