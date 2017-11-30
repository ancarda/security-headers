<?php

declare(strict_types=1);

namespace Test;

use \PHPUnit\Framework\TestCase;
use \Ancarda\Security\Header\ContentSecurityPolicy;

final class ContentSecurityPolicyTest extends TestCase
{
    public function testSetScripts()
    {
        $csp = new ContentSecurityPolicy;

        $csp = $csp->withScriptsFromSelf();
        $this->assertContains("script-src 'self'", $csp->compile());
        $csp = $csp->withScriptsFromDomain('example.com');
        $this->assertContains("script-src 'self' example.com", $csp->compile());
    }

    public function testSetStylesheets()
    {
        $csp = new ContentSecurityPolicy;

        $csp = $csp->withStylesheetsFromSelf();
        $this->assertContains("style-src 'self'", $csp->compile());
        $csp = $csp->withStylesheetsFromDomain('example.com');
        $this->assertContains("style-src 'self' example.com", $csp->compile());
    }

    public function testSetImages()
    {
        $csp = new ContentSecurityPolicy;

        $csp = $csp->withImagesFromSelf();
        $this->assertContains("img-src 'self'", $csp->compile());
        $csp = $csp->withImagesFromDomain('example.com');
        $this->assertContains("img-src 'self' example.com", $csp->compile());
    }

    public function testSetNonce()
    {
        $csp = new ContentSecurityPolicy;

        $csp = $csp->withNonce('phpunit');
        $value = $csp->compile();
        $this->assertContains("style-src 'nonce-phpunit'", $value);
        $this->assertContains("script-src 'nonce-phpunit'", $value);
    }

    public function testConnect()
    {
        $csp = new ContentSecurityPolicy;

        $csp = $csp->withConnectToSelf();
        $this->assertContains("connect-src 'self'", $csp->compile());
    }

    public function testChaining()
    {
        $csp = new ContentSecurityPolicy;

        $value = $csp
            ->withImagesFromSelf()
            ->withImagesFromDomain('example.com')
            ->withScriptsFromSelf()
            ->withScriptsFromDomain('js.example.com')
            ->withConnectToSelf()
            ->withNonce('phpunit-chain')
            ->compile();

        $this->assertContains("img-src 'self' example.com 'nonce-phpunit-chain'", $value);
        $this->assertContains("script-src 'self' js.example.com 'nonce-phpunit-chain'", $value);
        $this->assertContains("connect-src 'self'", $value);
    }
}
