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
        $this->assertContains("DENY", $xfo->compile());
    }

    public function testSameOrigin()
    {
        $xfo = new FrameOptions;
        $xfo = $xfo->withAllowFromSelf();
        $this->assertContains("SAMEORIGIN", $xfo->compile());
    }

    public function testAllowFromURI()
    {
        $xfo = new FrameOptions;
        $xfo = $xfo->withAllowFrom('http://example.com/');
        $this->assertContains("ALLOW-FROM http://example.com/", $xfo->compile());
    }

    public function testAllowFromDomain()
    {
        $xfo = new FrameOptions;
        $xfo = $xfo->withAllowFrom('example.com/');
        $this->assertContains("ALLOW-FROM http://example.com/", $xfo->compile());
        $xfo = $xfo->withAllowFrom('http://example.com');
        $this->assertContains("ALLOW-FROM http://example.com/", $xfo->compile());
        $xfo = $xfo->withAllowFrom('example.com');
        $this->assertContains("ALLOW-FROM http://example.com/", $xfo->compile());
    }
}
