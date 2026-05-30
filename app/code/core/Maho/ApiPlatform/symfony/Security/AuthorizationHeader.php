<?php

declare(strict_types=1);

/**
 * Maho
 *
 * @package    Maho_ApiPlatform
 * @copyright  Copyright (c) 2026 Maho (https://mahocommerce.com)
 * @license    https://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

namespace Maho\ApiPlatform\Security;

use Symfony\Component\HttpFoundation\Request;

/**
 * Single source of truth for reading a Bearer token off the Authorization
 * header, shared by the OAuth2 authenticator and the pre-firewall API
 * listeners so they all parse it identically.
 *
 * The pattern mirrors Symfony's HeaderAccessTokenExtractor (which this
 * project does not ship - symfony/security-http is not a dependency): the
 * `Bearer` scheme is matched case-sensitively, a token is required, and the
 * token must match the RFC 6750 token68 grammar.
 */
final class AuthorizationHeader
{
    /**
     * True only when the Authorization header carries a usable Bearer token —
     * a scheme-only `Bearer` (no token) returns false on purpose. Callers gate
     * on this to decide whether to engage the authenticator / defer to the
     * firewall, and a malformed tokenless header must not make a public
     * operation 401 before its access control is even consulted. Derived from
     * bearerToken() so the two can never disagree.
     */
    public static function hasBearerScheme(Request $request): bool
    {
        return self::bearerToken($request) !== null;
    }

    public static function bearerToken(Request $request): ?string
    {
        $header = $request->headers->get('Authorization');
        if ($header === null) {
            return null;
        }
        // Same pattern as Symfony's HeaderAccessTokenExtractor default:
        // case-sensitive scheme, whitespace separator, RFC 6750 token68 chars.
        if (preg_match('/^Bearer\s+([a-zA-Z0-9\-_+~.\/=]+)$/', $header, $m) !== 1) {
            return null;
        }
        return $m[1];
    }
}
