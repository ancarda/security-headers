<?php

declare(strict_types=1);

namespace Test;

use \PHPUnit\Framework\TestCase;
use \Ancarda\Security\Header\XssFilter;

final class XssFilterTest extends TestCase
{
    public function testBlank()
    {
        $xss = new XssFilter();
        $this->assertEquals('0', $xss->compile());
    }

    public function testFilterAndBlock()
    {
        $xss = new XssFilter();
        $xss = $xss->withFilterAndBlock();
        $this->assertEquals('1; mode=block', $xss->compile());
    }
}
