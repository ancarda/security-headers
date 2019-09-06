<?php

declare(strict_types=1);

namespace Ancarda\Security\Header;

use Ancarda\Security\Header\Exception\ValueTooSmallException;
use Ancarda\Security\Header\Exception\SupportingDirectiveNotActivatedException;

/**
 * Helper class to build a simple Strict-Transport-Security header.
 *
 * HTTP Strict Transport Security (HSTS) indicates to web-browsers that this
 * website should only be accessed via SSL/TLS. Until the timeout expires, web
 * browsers forcibly rewrite links destined for this website from http:// to
 * https://. With an active HSTS policy applied, it's not possible to load the
 * website over HTTP until the timeout expires.
 *
 * The timeout refreshes everytime a user loads a page that issues this header.
 * That is, if they load a page and are given the default timeout (six months),
 * and come back in two months time (policy valid for four more months), the
 * browser will reset the timeout back to six months. For frequent visitors,
 * who visit a site at least once every six months, they will never access the
 * website over HTTP.
 *
 * This policy is **never applied** if sent *over HTTP*. You must continue
 * redirecting your users to HTTPS so they can apply this header.
 *
 * Strict Transport Security is intended to help prevent users from having SSL
 * be stripped away by a malicious network operator. If their bookmark is HTTP
 * and they rely on the web server, not the browser, serving the redirect to
 * HTTPS, the network owner can intercept this unencrypted request and serve
 * them a plaintext page, performing SSL termination themselves.
 *
 * To apply this to the initial request, or help infrequent visitors, this
 * policy can be loaded into the source code of popular browsers, which is
 * known as 'Preloading'. See the withPreload() function for more information.
 *
 * @author  Mark Dain <mark@markdain.net>
 * @license https://choosealicense.com/licenses/mit/ (MIT License)
 */
final class StrictTransportSecurity implements StrictTransportSecurityInterface
{
    /**
     * @var int Timeout on this policy being active. Defaults to six months.
     */
    private $timeout = self::SIX_MONTHS;

    /**
     * @var bool If subdomains are included in this policy.
     */
    private $subdomains = false;

    /**
     * @var bool If this policy should be preloaded into browsers.
     */
    private $preload = false;

    public function name(): string
    {
        return 'Strict-Transport-Security';
    }

    public function withTimeout(int $age): StrictTransportSecurityInterface
    {
        if ($age < self::SIX_MONTHS) {
            throw new ValueTooSmallException(
                'The max-age directive should be at-least six months (' . self::SIX_MONTHS . '). ' .
                'The value you have given (' . $age . ') is too small.' . "\r\n" .
                'If you are testing HSTS and need to bypass this value, you can use withTimeoutUnsafe()'
            );
        }

        $clone = clone $this;
        $clone->timeout = $age;
        return $clone;
    }

    public function getTimeout(): int
    {
        return $this->timeout;
    }

    public function withSubdomains(): StrictTransportSecurityInterface
    {
        $clone = clone $this;
        $clone->subdomains = true;
        return $clone;
    }

    public function withPreload(): StrictTransportSecurityInterface
    {
        if (!$this->subdomains) {
            throw new SupportingDirectiveNotActivatedException(
                'Preload cannot be applied because this header does not apply to subdomains as well. ' .
                'You need to add ->withSubdomains() before this ->withPreload() call.'
            );
        }

        $clone = clone $this;
        $clone->preload = true;
        return $clone;
    }

    /**
     * Undocumented function that allows bypassing of max-age checks.
     *
     * This should only be used if you are testing HSTS and want a low value
     * max-age value. This function is intentionally hidden from phpDocumentor
     * as it's use is discouraged.
     *
     * @internal Hidden due to it's use being discouraged.
     * @param int $age
     * @return StrictTransportSecurity
     */
    public function withTimeoutUnsafe(int $age): self
    {
        $clone = clone $this;
        $clone->timeout = $age;
        return $clone;
    }

    public function compile(): string
    {
        return 'max-age=' . $this->timeout .
            ($this->subdomains ? '; includeSubDomains' : '') .
            ($this->preload ? '; preload' : '')
            ;
    }
}
