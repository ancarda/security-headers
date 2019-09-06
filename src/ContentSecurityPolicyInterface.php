<?php

declare(strict_types=1);

namespace Ancarda\Security\Header;

/**
 * Helper class to build a simple Content-Security-Policy header
 *
 * To use this class, instantiate it, and use the with() methods to build up a
 * whitelist of where stylesheets and scripts can come from, as well as where
 * connections (XMLHttpRequest and WebSocket) are permitted to go to.
 *
 * You could use this library as follows:
 *
 *     $csp = new ContentSecurityPolicy();
 *     $csp = $csp->withScriptsFromDomain('example.com');
 *     $csp = $csp->withStylesheetsFromSelf();
 *     header('Content-SecurityPolicy: ' . $csp->compile());
 *
 * Alternatively, you may chain these calls:
 *
 *     $csp = new ContentSecurityPolicy();
 *     header('Content-Security-Policy: ' . $csp
 *         ->withScriptsFromDomain('example.com')
 *         ->withStylesheetsFromSelf()
 *         ->compile());
 *
 * Once you are done, call compile() to get the header value. You can now pass
 * this to whatever method you use to set HTTP response headers.
 *
 * Everything defaults to denied.
 */
interface ContentSecurityPolicyInterface extends HeaderInterface
{
    /**
     * Returns the Content Security Policy nonce value that allows inline content to
     * be rendered and executed.
     *
     * @return string
     */
    public function getNonce(): string;

    /**
     * Sets the nonce value used in this policy.
     *
     * A suitable, random nonce is automatically generated by the constructor, but
     * may be changed by this method. The nonce should be at-least 32 characters
     * long.
     *
     * @param string $nonce Random nonce, at-least 32 characters
     * @return ContentSecurityPolicyInterface
     */
    public function withNonce(string $nonce): ContentSecurityPolicyInterface;

    /**
     * Whitelists executing scripts from the specified domain.
     *
     * @param string $domain Domain to add
     * @return ContentSecurityPolicyInterface
     */
    public function withScriptsFromDomain(string $domain): ContentSecurityPolicyInterface;

    /**
     * Whitelists executing scripts on the same domain the policy is active on.
     *
     * @return ContentSecurityPolicyInterface
     */
    public function withScriptsFromSelf(): ContentSecurityPolicyInterface;

    /**
     * Whitelists connecting (XMLHttpRequest and WebSockets) to same domain the
     * policy is active on.
     *
     * @return ContentSecurityPolicyInterface
     */
    public function withConnectToSelf(): ContentSecurityPolicyInterface;

    /**
     * Whitelists rendering stylesheets from the specified domain.
     *
     * @param string $domain Domain to add
     * @return ContentSecurityPolicyInterface
     */
    public function withStylesheetsFromDomain(string $domain): ContentSecurityPolicyInterface;

    /**
     * Whitelists rendering stylesheets on the same domain the policy is active on.
     *
     * @return ContentSecurityPolicyInterface
     */
    public function withStylesheetsFromSelf(): ContentSecurityPolicyInterface;

    /**
     * Whitelists displaying images from the specified domain.
     *
     * @param string $domain Domain to add
     * @return ContentSecurityPolicyInterface
     */
    public function withImagesFromDomain(string $domain): ContentSecurityPolicyInterface;

    /**
     * Whitelists displaying images on the same domain the policy is active on.
     *
     * @return ContentSecurityPolicyInterface
     */
    public function withImagesFromSelf(): ContentSecurityPolicyInterface;
}