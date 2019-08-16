<?php

declare(strict_types=1);

namespace Test;

use \PHPUnit\Framework\TestCase;
use \Ancarda\Security\Header\ContentSecurityPolicy;

final class ContentSecurityPolicyTest extends TestCase
{
    public function testSetScripts(): void
    {
        $csp = new ContentSecurityPolicy();

        $csp = $csp->withScriptsFromSelf();
        static::assertContains("script-src 'self'", $csp->compile());
        $csp = $csp->withScriptsFromDomain('example.com');
        static::assertContains("script-src 'self' example.com", $csp->compile());
    }

    public function testSetStylesheets(): void
    {
        $csp = new ContentSecurityPolicy();

        $csp = $csp->withStylesheetsFromSelf();
        static::assertContains("style-src 'self'", $csp->compile());
        $csp = $csp->withStylesheetsFromDomain('example.com');
        static::assertContains("style-src 'self' example.com", $csp->compile());
    }

    public function testSetImages(): void
    {
        $csp = new ContentSecurityPolicy();

        $csp = $csp->withImagesFromSelf();
        static::assertContains("img-src 'self'", $csp->compile());
        $csp = $csp->withImagesFromDomain('example.com');
        static::assertContains("img-src 'self' example.com", $csp->compile());
    }

    public function testSetNonce(): void
    {
        $csp = new ContentSecurityPolicy();

        $csp = $csp->withNonce('phpunit');
        static::assertEquals($csp->getNonce(), 'phpunit');
        $value = $csp->compile();
        static::assertContains("style-src 'nonce-phpunit'", $value);
        static::assertContains("script-src 'nonce-phpunit'", $value);
    }

    public function testConnect(): void
    {
        $csp = new ContentSecurityPolicy();

        $csp = $csp->withConnectToSelf();
        static::assertContains("connect-src 'self'", $csp->compile());
    }

    public function testChaining(): void
    {
        $csp = new ContentSecurityPolicy();

        $value = $csp
            ->withImagesFromSelf()
            ->withImagesFromDomain('example.com')
            ->withScriptsFromSelf()
            ->withScriptsFromDomain('js.example.com')
            ->withConnectToSelf()
            ->withNonce('phpunit-chain')
            ->compile();

        static::assertContains("img-src 'self' example.com 'nonce-phpunit-chain'", $value);
        static::assertContains("script-src 'self' js.example.com 'nonce-phpunit-chain'", $value);
        static::assertContains("connect-src 'self'", $value);
    }
}
