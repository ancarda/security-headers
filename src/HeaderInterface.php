<?php

declare(strict_types=1);

namespace Ancarda\Security\Header;

/**
 * The common interface that all HTTP headers must implement
 *
 * Provides generic support for what's common in all HTTP headers; a name and
 * a value that can be generated or retrieved
 */
interface HeaderInterface
{
    /**
     * Returns the name of this header when expressed over the network
     *
     * @return string e.g. X-Xss-Protection
     */
    public function name(): string;

    /**
     * Returns the computed value of this header
     *
     * This function MUST NOT throw an exception; all the setter methods must
     * have prevented this header from getting into an inconsistent or invalid
     * state
     *
     * @return string
     */
    public function compile(): string;
}
