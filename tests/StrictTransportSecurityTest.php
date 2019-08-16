<?php

declare(strict_types=1);

namespace Test;

use \PHPUnit\Framework\TestCase;
use \Ancarda\Security\Header\StrictTransportSecurity;
use \Ancarda\Security\Header\Exception\SupportingDirectiveNotActivatedException;
use \Ancarda\Security\Header\Exception\ValueTooSmallException;

final class StrictTransportSecurityTest extends TestCase
{
    public function testDefaultIs6Months(): void
    {
        $sts = new StrictTransportSecurity();
        static::assertEquals('max-age=15778800', $sts->compile());
    }

    public function testRejectingLowTimeoutValues(): void
    {
        $sts = new StrictTransportSecurity();
        $this->expectException(ValueTooSmallException::class);
        $sts->withTimeout(300);
    }

    public function testSettingTimeout(): void
    {
        $sts = new StrictTransportSecurity();
        $sts = $sts->withTimeout(31557600);
        static::assertEquals('max-age=31557600', $sts->compile());
    }

    public function testAllowBypassingTimeoutWarning(): void
    {
        $sts = new StrictTransportSecurity();
        $sts = $sts->withTimeoutUnsafe(300);
        static::assertEquals('max-age=300', $sts->compile());
    }

    public function testSubdomains(): void
    {
        $sts = new StrictTransportSecurity();
        $sts = $sts->withSubdomains();
        static::assertEquals('max-age=15778800; includeSubDomains', $sts->compile());
    }

    public function testRejectingPreloadWithoutSubdomains(): void
    {
        $sts = new StrictTransportSecurity();
        $this->expectException(SupportingDirectiveNotActivatedException::class);
        $sts->withPreload();
    }

    public function testPreload(): void
    {
        $sts = new StrictTransportSecurity();
        $sts = $sts->withSubdomains()->withPreload();
        static::assertEquals('max-age=15778800; includeSubDomains; preload', $sts->compile());
    }
}
