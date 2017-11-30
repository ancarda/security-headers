<?php

declare(strict_types=1);

namespace Test;

use \PHPUnit\Framework\TestCase;
use \Ancarda\Security\Header\FrameOptions;

class FrameOptionsTest extends TestCase
{
    public function testBlank()
    {
        $xfo = new FrameOptions;
        $this->assertContains("DENY", $xfo->compile());
    }

    public function testSameOrigin()
    {
        $xfo = new FrameOptions;
        $xfo = $xfo->usingAllowFromSelf();
        $this->assertContains("SAMEORIGIN", $xfo->compile());
    }

    public function testAllowFromURI()
    {
        $xfo = new FrameOptions;
        $xfo = $xfo->usingAllowFrom('http://example.com/');
        $this->assertContains("ALLOW-FROM http://example.com/", $xfo->compile());
    }

    public function testAllowFromDomain()
    {
        $xfo = new FrameOptions;
        $xfo = $xfo->usingAllowFrom('example.com/');
        $this->assertContains("ALLOW-FROM http://example.com/", $xfo->compile());
        $xfo = $xfo->usingAllowFrom('http://example.com');
        $this->assertContains("ALLOW-FROM http://example.com/", $xfo->compile());
        $xfo = $xfo->usingAllowFrom('example.com');
        $this->assertContains("ALLOW-FROM http://example.com/", $xfo->compile());
    }
}
