<?php

declare(strict_types=1);

namespace Test;

use Ancarda\Security\Header\Exception\SupportingDirectiveNotActivatedException;
use Ancarda\Security\Header\Exception\ValueTooSmallException;
use Ancarda\Security\Header\StrictTransportSecurity;
use Ancarda\Security\Header\StrictTransportSecurityInterface;
use PHPUnit\Framework\TestCase;

final class StrictTransportSecurityTest extends TestCase
{
    public function testImplementsHeaderInterface(): void
    {
        $sts = new StrictTransportSecurity();
        static::assertSame('Strict-Transport-Security', $sts->name());
    }

    public function testDefaultIs6Months(): void
    {
        $sts = new StrictTransportSecurity();
        static::assertEquals(StrictTransportSecurityInterface::SIX_MONTHS, $sts->getTimeout());
        static::assertEquals('max-age=15778800', $sts->compile());
    }

    public function testRejectingLowTimeoutValues(): void
    {
        $sts = new StrictTransportSecurity();
        $this->expectException(ValueTooSmallException::class);
        $sts->withTimeout(300);
    }

    public function testRejectingTimeoutBelowSixMonths(): void
    {
        $sts = new StrictTransportSecurity();
        $this->expectException(ValueTooSmallException::class);
        $sts->withTimeout(StrictTransportSecurityInterface::SIX_MONTHS - 1);
    }

    public function testAcceptTimeoutAtSixMonths(): void
    {
        $sts = new StrictTransportSecurity();
        $sts->withTimeout(StrictTransportSecurityInterface::SIX_MONTHS);
        static::assertEquals(StrictTransportSecurityInterface::SIX_MONTHS, $sts->getTimeout());
        static::assertEquals('max-age=' . StrictTransportSecurityInterface::SIX_MONTHS, $sts->compile());
    }

    public function testSettingTimeout(): void
    {
        $sts = new StrictTransportSecurity();
        $sts = $sts->withTimeout(31557600);
        static::assertEquals(31557600, $sts->getTimeout());
        static::assertEquals('max-age=31557600', $sts->compile());
    }

    public function testAllowBypassingTimeoutWarning(): void
    {
        $sts = new StrictTransportSecurity();
        $sts = $sts->withTimeoutUnsafe(300);
        static::assertEquals(300, $sts->getTimeout());
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
