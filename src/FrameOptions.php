<?php

declare(strict_types=1);

namespace Ancarda\Security\Header;

/**
 * Helper class to build a simple X-Frame-Options header.
 *
 * @author  Mark Dain <mark@markdain.net>
 * @license https://choosealicense.com/licenses/mit/ (MIT License)
 */
final class FrameOptions implements FrameOptionsInterface
{
    /** @var string */
    private $xfo = 'DENY';

    public function name(): string
    {
        return 'X-Frame-Options';
    }

    public function withAllowFromSelf(): FrameOptionsInterface
    {
        $clone = clone $this;
        $clone->xfo = 'SAMEORIGIN';
        return $clone;
    }

    public function withAllowFrom(string $domain): FrameOptionsInterface
    {
        if (substr($domain, -1) !== '/') {
            return $this->withAllowFrom($domain . '/');
        }

        if (strpos($domain, 'http') !== 0) {
            return $this->withAllowFrom('http://' . $domain);
        }

        $clone = clone $this;
        $clone->xfo = 'ALLOW-FROM ' . $domain;
        return $clone;
    }

    public function compile(): string
    {
        return $this->xfo;
    }
}
