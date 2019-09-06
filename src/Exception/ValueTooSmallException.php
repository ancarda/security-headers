<?php

declare(strict_types=1);

namespace Ancarda\Security\Header\Exception;

use Ancarda\Security\Header\Exception;

/**
 * This exception is thrown when a given value is too small to be acceptable.
 *
 * Usage of this exception will vary across classes in this package, however
 * it's often used for a timeout. Long Time To Live values on security headers
 * can be beneficial because browsers will cache them. This means users will be
 * protected for longer if they are infrequent visitors.
 *
 * @author  Mark Dain <mark@markdain.net>
 * @license https://choosealicense.com/licenses/mit/ (MIT License)
 */
final class ValueTooSmallException extends Exception
{
    // Class left intentionally blank.
}
