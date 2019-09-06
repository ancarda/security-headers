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
 */
interface XssFilterInterface extends HeaderInterface
{
    /**
     * Request the browser activate it's XSS filter and on suspected reflected
     * XSS, prevent the page from loading
     *
     * @return XssFilterInterface
     */
    public function withFilterAndBlock(): XssFilterInterface;
}
