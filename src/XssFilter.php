<?php

declare(strict_types=1);

namespace Ancarda\Security\Header;

/**
 * Helper class to build a simple X-Xss-Protection header.
 *
 * This class is immutable, so the `with` methods return a new instance of this
 * class with the changes you requested. Any function here that returns an instance
 * of XssFilter isn't making any changes to the current object.
 *
 * @package Ancarda_Security_Headers
 * @author  Mark Dain <mark@markdain.net>
 * @license https://choosealicense.com/licenses/mit/ (MIT License)
 */
final class XssFilter
{
    /**
     * Default to disabling the XSS filter from running.
     *
     * This is a difficult choice to make but it must be made. Without specifying
     * an X-Xss-Protection value, the filter defaults to '1' which means to try to
     * prevent a reflected XSS attack by removing code, but leave the rest of the
     * page executing.
     *
     * This has been used to steal OAuth tokens on Facebook which is why their
     * X-Xss-Protection header is 0 now.
     *
     * A filter value of 1 without mode=block allows an attacker to trick the XSS
     * filter to remove bits of information from the page but continue executing.
     *
     * By applying zero, we request the browser to disable it's XSS filter. With a
     * strong Content Security Policy and proper HTML handling, XSS is far less
     * likely to be damaging and can be mitigated through bug fixes both in PHP
     * and JavaScript.
     *
     * Ultimately, it comes down to where we want to fix XSS problems; by using a
     * magic filter in the browser, or fixing every bit of code that may be
     * affected. I can absolutely appreciate why some prefer the former.
     *
     * Security is very hard. I hope this won't be a huge mistake.
     *
     * @var string XSS Filter setting. Defaults to disabled.
     */
    private $value = '0';

    /**
     * Request the browser activate it's XSS filter and on suspected reflected
     * XSS, prevent the page from loading.
     *
     * @return XssFilter
     */
    public function withFilterAndBlock(): XssFilter
    {
        $clone = clone $this;
        $clone->value = '1; mode=block';
        return $clone;
    }

    /**
     * Returns the compiled X-Xss-Protection header value.
     *
     * @return string
     */
    public function compile(): string
    {
        return $this->value;
    }
}
