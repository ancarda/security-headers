<?php

declare(strict_types=1);

namespace Ancarda\Security\Header;

use Exception;

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
 *
 * @author  Mark Dain <mark@markdain.net>
 * @license https://choosealicense.com/licenses/mit/ (MIT License)
 */
final class ContentSecurityPolicy implements ContentSecurityPolicyInterface
{
    /**
     * Array of domains, used to track what endpoints are whitelisted for what.
     *
     * @var array
     */
    private $domains   = [
        'scripts'     => [],
        'stylesheets' => [],
        'images'      => [],
    ];

    /**
     * Array of booleans, used to track if access from self for various things is
     * whitelisted or not.
     *
     * @var bool[]
     */
    private $self = [
        'connect'     => false,
        'scripts'     => false,
        'stylesheets' => false,
        'images'      => false,
    ];

    /** @var string */
    private $nonce = null;

    /**
     * Creates a new instance of the Content Security Policy builder class.
     *
     * This function will randomly generate a nonce value using random_bytes().
     *
     * @throws Exception If a nonce cannot be generated
     */
    public function __construct()
    {
        $this->nonce = bin2hex(random_bytes(16));
    }

    /**
     * Returns the name of this header's when expressed over the network
     *
     * @return string
     */
    public function name(): string
    {
        return 'Content-Security-Policy';
    }

    public function getNonce(): string
    {
        return $this->nonce;
    }

    public function withNonce(string $nonce): ContentSecurityPolicyInterface
    {
        $clone = clone $this;
        $clone->nonce = $nonce;
        return $clone;
    }

    public function withScriptsFromDomain(string $domain): ContentSecurityPolicyInterface
    {
        $clone = clone $this;
        $clone->whitelistDomain('scripts', $domain);
        return $clone;
    }

    public function withScriptsFromSelf(): ContentSecurityPolicyInterface
    {
        $clone = clone $this;
        $clone->self['scripts'] = true;
        return $clone;
    }

    public function withConnectToSelf(): ContentSecurityPolicyInterface
    {
        $clone = clone $this;
        $clone->self['connect'] = true;
        return $clone;
    }

    public function withStylesheetsFromDomain(string $domain): ContentSecurityPolicyInterface
    {
        $clone = clone $this;
        $clone->whitelistDomain('stylesheets', $domain);
        return $clone;
    }

    public function withStylesheetsFromSelf(): ContentSecurityPolicyInterface
    {
        $clone = clone $this;
        $clone->self['stylesheets'] = true;
        return $clone;
    }

    public function withImagesFromDomain(string $domain): ContentSecurityPolicyInterface
    {
        $clone = clone $this;
        $clone->whitelistDomain('images', $domain);
        return $clone;
    }

    public function withImagesFromSelf(): ContentSecurityPolicyInterface
    {
        $clone = clone $this;
        $clone->self['images'] = true;
        return $clone;
    }

    private function whitelistDomain(string $bucket, string $domain): void
    {
        if (!in_array($domain, $this->domains[$bucket], true)) {
            $this->domains[$bucket][] = $domain;
        }
    }

    public function compile(): string
    {
        $out = 'default-src \'none\'; ';

        $script = 'script-src ';
        if ($this->self['scripts']) {
            $script .= '\'self\' ';
        }
        foreach ($this->domains['scripts'] as $s) {
            $script .= $s . ' ';
        }
        $script .= '\'nonce-' . $this->nonce . '\'';
        $out .= trim($script) . '; ';

        $style = 'style-src ';
        if ($this->self['stylesheets']) {
            $style .= '\'self\' ';
        }
        foreach ($this->domains['stylesheets'] as $s) {
            $style .= $s . ' ';
        }
        $style .= '\'nonce-' . $this->nonce . '\'';
        $out .= trim($style) . '; ';

        if ($this->self['connect']) {
            $out .= 'connect-src \'self\'; ';
        }

        $images = 'img-src ';
        if ($this->self['images']) {
            $images .= '\'self\' ';
        }
        foreach ($this->domains['images'] as $s) {
            $images .= $s . ' ';
        }
        $images .= '\'nonce-' . $this->nonce . '\'';
        $out .= trim($images) . '; ';

        return trim($out);
    }
}
