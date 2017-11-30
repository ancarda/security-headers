<?php

declare(strict_types=1);

namespace Ancarda\Security\Header;

/**
 * Helper class to build a simple X-Frame-Options header.
 *
 * @package Ancarda_Security_Headers
 * @author  Mark Dain <mark@markdain.net>
 * @license https://choosealicense.com/licenses/mit/ (MIT License)
 */
final class FrameOptions
{
    /**
     * The X-Frame-Options value. Defaults to denying all frames.
     *
     * @var string
     */
    private $xfo = 'DENY';

    /**
     * Allows this website to be embedded in iframes on the same domain.
     *
     * @return FrameOptions
     */
    public function usingAllowFromSelf(): FrameOptions
    {
        $clone = clone $this;
        $clone->xfo = 'SAMEORIGIN';
        return $clone;
    }

    /**
     * Allows this page to be framed from a specific domain.
     *
     * This function takes a URL that includes a host and a prefix, but no path,
     * query, or fragment. For example, `http://example.com`. A trailing slash is
     * allowed on the end. This function can also accept a domain, `example.com`.
     *
     * @param string $domain URL including a prefix, but without a path.
     * @return FrameOptions
     */
    public function usingAllowFrom(string $domain): FrameOptions
    {
        if (substr($domain, -1) !== '/') {
            return $this->usingAllowFrom($domain . '/');
        }

        if (strpos($domain, 'http') !== 0) {
            return $this->usingAllowFrom('http://' . $domain);
        }

        $clone = clone $this;
        $clone->xfo = 'ALLOW-FROM ' . $domain;
        return $clone;
    }

    /**
     * Returns the compiled X-Frame-Options header value.
     *
     * @return string
     */
    public function compile(): string
    {
        return $this->xfo;
    }
}
