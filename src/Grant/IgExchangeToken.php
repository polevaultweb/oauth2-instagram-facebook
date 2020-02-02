<?php

namespace League\OAuth2\Client\Grant;

/**
 * Represents an exchange token grant.
 */
class IgExchangeToken extends AbstractGrant
{
    /**
     * @inheritdoc
     */
    protected function getName()
    {
        return 'ig_exchange_token';
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