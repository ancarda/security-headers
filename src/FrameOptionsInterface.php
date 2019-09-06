<?php

declare(strict_types=1);

namespace Ancarda\Security\Header;

/**
 * Helper class to build a simple X-Frame-Options header.
 */
interface FrameOptionsInterface extends HeaderInterface
{
    /**
     * Allows this website to be embedded in iframes on the same domain.
     *
     * @return FrameOptionsInterface
     */
    public function withAllowFromSelf(): FrameOptionsInterface;

    /**
     * Allows this page to be framed from a specific domain.
     *
     * This function takes a URL that includes a host and a prefix, but no path,
     * query, or fragment. For example, `http://example.com`. A trailing slash is
     * allowed on the end. This function can also accept a domain, `example.com`.
     *
     * @param string $domain URL including a prefix, but without a path.
     * @return FrameOptionsInterface
     */
    public function withAllowFrom(string $domain): FrameOptionsInterface;
}
