<?php

namespace League\OAuth2\Client\Grant;

/**
 * Represents an refresh token grant.
 */
class IgRefreshToken extends AbstractGrant
{
    /**
     * @inheritdoc
     */
    protected function getName()
    {
        return 'ig_refresh_token';
    }

    /**
     * @inheritdoc
     */
    protected function getRequiredRequestParameters()
    {
        return [
            'access_token',
        ];
    }
}