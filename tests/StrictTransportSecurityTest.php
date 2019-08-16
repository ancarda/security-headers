<?php

declare(strict_types=1);

namespace Test;

use \PHPUnit\Framework\TestCase;
use \Ancarda\Security\Header\StrictTransportSecurity;
use \Ancarda\Security\Header\Exception\SupportingDirectiveNotActivatedException;
use \Ancarda\Security\Header\Exception\ValueTooSmallException;

final class StrictTransportSecurityTest extends TestCase
{
    public function testDefaultIs6Months()
    {
        $sts = new StrictTransportSecurity();
        $this->assertEquals('max-age=15778800', $sts->compile());
    }

    public function testRejectingLowTimeoutValues()
    {
        $sts = new StrictTransportSecurity();
        $this->expectException(ValueTooSmallException::class);
        $sts->withTimeout(300);
    }

    public function testSettingTimeout()
    {
        $sts = new StrictTransportSecurity();
        $sts = $sts->withTimeout(31557600);
        $this->assertEquals('max-age=31557600', $sts->compile());
    }

    public function testAllowBypassingTimeoutWarning()
    {
        $sts = new StrictTransportSecurity();
        $sts = $sts->withTimeoutUnsafe(300);
        $this->assertEquals('max-age=300', $sts->compile());
    }

    public function testSubdomains()
    {
        $sts = new StrictTransportSecurity();
        $sts = $sts->withSubdomains();
        $this->assertEquals('max-age=15778800; includeSubDomains', $sts->compile());
    }

    public function testRejectingPreloadWithoutSubdomains()
    {
        $sts = new StrictTransportSecurity();
        $this->expectException(SupportingDirectiveNotActivatedException::class);
        $sts->withPreload();
    }

    public function testPreload()
    {
        $sts = new StrictTransportSecurity();
        $sts = $sts->withSubdomains()->withPreload();
        $this->assertEquals('max-age=15778800; includeSubDomains; preload', $sts->compile());
    }
}
