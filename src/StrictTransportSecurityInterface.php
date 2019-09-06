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
 */
interface StrictTransportSecurityInterface extends HeaderInterface
{
    /**
     * @var int The number of seconds usually elapsed in six months (15778800)
     */
    const SIX_MONTHS = 15778800;

    /**
     * @var int The number of seconds usually elapsed in a year (31557600)
     */
    const ONE_YEAR = 31557600;

    /**
     * Sets the timeout for this policy.
     *
     * This function will throw an exception if the given timeout is below six
     * months. The value cannot be too low, else it loses it's effectiveness,
     * especially for infrequent visitors.
     *
     * @param int $age
     * @throws ValueTooSmallException
     * @return StrictTransportSecurityInterface
     */
    public function withTimeout(int $age): StrictTransportSecurityInterface;

    /**
     * Retrieve the timeout in this policy.
     *
     * @return int
     */
    public function getTimeout(): int;

    /**
     * Indicates this policy should be applied to subdomains like www.
     *
     * @return StrictTransportSecurityInterface
     */
    public function withSubdomains(): StrictTransportSecurityInterface;

    /**
     * Indicates this domain would like to be preloaded.
     *
     * The preload list is built into browsers and contains a list of websites
     * that will only be accessed using HTTPS. This has the same effect as if
     * a browser had an HSTS header cached, but preloaded entries do not expire
     * and are naturally always active.
     *
     * Once you have added this header, you should submit your site on
     * https://hstspreload.org/
     *
     * **WARNING:** Once you are on the HSTS preload list, it's difficult to
     * get off as it would require users to update their browsers. Submitting
     * a preload request (and issuing a preload header) should only be done if
     * you are very confident in your SSL implementation.
     *
     * This function will throw an exception if this policy is not active for
     * subdomains, as a preload is only applied to an entire domain, never
     * on a per-subdomain basis.
     *
     * @throws SupportingDirectiveNotActivatedException
     *     If called without withSubdomains
     * @return StrictTransportSecurityInterface
     */
    public function withPreload(): StrictTransportSecurityInterface;
}
