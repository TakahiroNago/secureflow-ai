<?php

namespace App\Security\Scanning\Detectors;

use App\Security\Scanning\Detection;
use App\Security\Scanning\NormalizedText;
use App\Security\Scanning\ScanFailure;

interface Detector
{
    /**
     * @return list<Detection>
     *
     * @throws ScanFailure
     */
    public function detect(NormalizedText $text): array;
}
