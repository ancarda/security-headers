<?php

declare(strict_types=1);

namespace Ancarda\Security\Header;

/**
 * Helper class to build a simple X-Xss-Protection header.
 *
 * @deprecated Deprecated in Chrome. Never implemented in Firefox.
 *   Removed in Edge
 *
 *   It has largely been replaced by Content-Security-Policy. When your CSP
 *   policy does not permit `unsafe-inline`, all inline JavaScript won't
 *   execute, meaning an XSS Filter isn't nearly as useful as it used to be
 * @author  Mark Dain <mark@markdain.net>
 * @license https://choosealicense.com/licenses/mit/ (MIT License)
 */
final class XssFilter implements XssFilterInterface
{
    /**
     * Default to disabling the XSS filter from running.
     *
     * This is a difficult choice to make but it must be made. Without
     * specifying an X-Xss-Protection header, the filter defaults to '1' which
     * means to try to prevent a reflected XSS attack by removing code, but
     * leave the rest of the page executing.
     *
     * This has been used to steal OAuth tokens on Facebook which is why their
     * X-Xss-Protection header is 0 now.
     *
     * A filter value of 1 without mode=block allows an attacker to trick the
     * XSS filter to remove bits of information from the page but continue
     * executing.
     *
     * By applying zero, we request the browser to disable it's XSS filter.
     * With a strong Content Security Policy and proper input handling,
     * reflected XSS is less likely to be a problem and should be mitigated
     * through fixes in the client side JavaScript.
     *
     * Ultimately, it comes down to where we want to fix reflected XSS; with a
     * magic filter in the browser, or by fixing every bit of code that may be
     * affected. I can absolutely appreciate why some prefer the former.
     *
     * Security is very hard. I hope this won't be a huge mistake.
     *
     * @var string XSS Filter setting. Defaults to disabled.
     */
    private $value = '0';

    public function name(): string
    {
        return 'X-Xss-Protection';
    }

    public function withFilterAndBlock(): XssFilterInterface
    {
        $clone = clone $this;
        $clone->value = '1; mode=block';
        return $clone;
    }

    public function compile(): string
    {
        return $this->value;
    }
}
