<?php

declare(strict_types=1);

namespace Test;

use \PHPUnit\Framework\TestCase;
use \Ancarda\Security\Header\FrameOptions;

final class FrameOptionsTest extends TestCase
{
    public function testBlank()
    {
        $xfo = new FrameOptions;
        $this->assertEquals("DENY", $xfo->compile());
    }

    public function testSameOrigin()
    {
        $xfo = new FrameOptions;
        $xfo = $xfo->withAllowFromSelf();
        $this->assertEquals("SAMEORIGIN", $xfo->compile());
    }

    public function testAllowFromURI()
    {
        $xfo = new FrameOptions;
        $xfo = $xfo->withAllowFrom('http://example.com/');
        $this->assertEquals("ALLOW-FROM http://example.com/", $xfo->compile());
    }

    public function testAllowFromDomain()
    {
        $xfo = new FrameOptions;
        $xfo = $xfo->withAllowFrom('example.com/');
        $this->assertEquals("ALLOW-FROM http://example.com/", $xfo->compile());
        $xfo = $xfo->withAllowFrom('http://example.com');
        $this->assertEquals("ALLOW-FROM http://example.com/", $xfo->compile());
        $xfo = $xfo->withAllowFrom('example.com');
        $this->assertEquals("ALLOW-FROM http://example.com/", $xfo->compile());
    }
}
