<?php

declare(strict_types=1);

namespace Test;

use Ancarda\Security\Header\XssFilter;
use PHPUnit\Framework\TestCase;

final class XssFilterTest extends TestCase
{
    public function testImplementsHeaderInterface(): void
    {
        $xss = new XssFilter();
        static::assertSame('X-Xss-Protection', $xss->name());
    }

    public function testBlank(): void
    {
        $xss = new XssFilter();
        static::assertEquals('0', $xss->compile());
    }

    public function testFilterAndBlock(): void
    {
        $xss = new XssFilter();
        $xss = $xss->withFilterAndBlock();
        static::assertEquals('1; mode=block', $xss->compile());
    }
}
