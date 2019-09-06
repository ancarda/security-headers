<?php

declare(strict_types=1);

namespace Test;

use Ancarda\Security\Header\FrameOptions;
use PHPUnit\Framework\TestCase;

final class FrameOptionsTest extends TestCase
{
    public function testImplementsHeaderInterface(): void
    {
        $xfo = new FrameOptions();
        static::assertSame('X-Frame-Options', $xfo->name());
    }

    public function testBlank(): void
    {
        $xfo = new FrameOptions();
        static::assertEquals("DENY", $xfo->compile());
    }

    public function testSameOrigin(): void
    {
        $xfo = new FrameOptions();
        $xfo = $xfo->withAllowFromSelf();
        static::assertEquals("SAMEORIGIN", $xfo->compile());
    }

    public function testAllowFromURI(): void
    {
        $xfo = new FrameOptions();
        $xfo = $xfo->withAllowFrom('http://example.com/');
        static::assertEquals("ALLOW-FROM http://example.com/", $xfo->compile());
    }

    public function testAllowFromDomain(): void
    {
        $xfo = new FrameOptions();
        $xfo = $xfo->withAllowFrom('example.com/');
        static::assertEquals("ALLOW-FROM http://example.com/", $xfo->compile());
        $xfo = $xfo->withAllowFrom('http://example.com');
        static::assertEquals("ALLOW-FROM http://example.com/", $xfo->compile());
        $xfo = $xfo->withAllowFrom('example.com');
        static::assertEquals("ALLOW-FROM http://example.com/", $xfo->compile());
    }
}
