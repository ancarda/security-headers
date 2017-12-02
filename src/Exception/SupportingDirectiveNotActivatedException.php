<?php

declare(strict_types=1);

namespace Ancarda\Security\Header\Exception;

use \Ancarda\Security\Header\Exception;

/**
 * This exception is thrown when another action that must be taken beforehand
 * hasn't been done.
 *
 * An example use of this exception is when a security header has multiple
 * levels of security, and a user has attempted to go up too fast without
 * setting up the previous levels.
 *
 * @package Ancarda_Security_Headers
 * @author  Mark Dain <mark@markdain.net>
 * @license https://choosealicense.com/licenses/mit/ (MIT License)
 */
final class SupportingDirectiveNotActivatedException extends Exception
{
    // Class left intentionally blank.
}
