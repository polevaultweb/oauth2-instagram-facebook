<?php

namespace League\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\Exception\InstagramFacebookIdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class InstagramFacebook extends AbstractProvider
{
	/**
	 * @var string Key used in a token response to identify the resource owner.
	 */
	const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'user.id';

	/**
	 * Default scopes
	 *
	 * @var array
	 */
	public $defaultScopes = [ 'user_profile', 'user_media' ];

	/**
	 * Default host
	 *
	 * @var string
	 */
	protected $host = 'https://api.instagram.com';

	/**
	 * Default host
	 *
	 * @var string
	 */
	protected $facebookHost = 'https://graph.instagram.com';

	/**
	 * Gets host.
	 *
	 * @return string
	 */
	public function getHost()
	{
		return $this->host;
	}

	/**
	 * Get the string used to separate scopes.
	 *
	 * @return string
	 */
	protected function getScopeSeparator()
	{
		return ' ';
	}

	/**
	 * Get authorization url to begin OAuth flow
	 *
	 * @return string
	 */
	public function getBaseAuthorizationUrl()
	{
		return $this->host.'/oauth/authorize';
	}

	/**
	 * Get access token url to retrieve token
	 *
	 * @param  array $params
	 *
	 * @return string
	 */
	public function getBaseAccessTokenUrl(array $params)
	{
		return $this->host.'/oauth/access_token';
	}

	/**
	 * Get access token url to retrieve token
	 *
	 * @param  array $params
	 *
	 * @return string
	 */
	public function getBaseLongLivedAccessTokenUrl(array $params)
	{
        $url   = $this->facebookHost . '/access_token';
        $query = $this->getAccessTokenQuery($params);
        return $this->appendQuery($url, $query);
	}

	/**
	 * Get access token url to retrieve token
	 *
	 * @param  array $params
	 *
	 * @return string
	 */
	public function getRefreshAccessTokenUrl(array $params)
	{
		$url   = $this->facebookHost . '/refresh_access_token';
		$query = $this->getAccessTokenQuery($params);
		return $this->appendQuery($url, $query);
	}

	/**
	 * Get provider url to fetch user details
	 *
	 * @param  AccessToken $token
	 *
	 * @return string
	 */
	public function getResourceOwnerDetailsUrl(AccessToken $token)
	{
		return $this->facebookHost.'/me?access_token='.$token;
	}

	/**
	 * Returns an authenticated PSR-7 request instance.
	 *
	 * @param  string $method
	 * @param  string $url
	 * @param  AccessToken|string $token
	 * @param  array $options Any of "headers", "body", and "protocolVersion".
	 *
	 * @return \Psr\Http\Message\RequestInterface
	 */
	public function getAuthenticatedRequest($method, $url, $token, array $options = [])
	{
		$parsedUrl = parse_url($url);
		$queryString = array();

		if (isset($parsedUrl['query'])) {
			parse_str($parsedUrl['query'], $queryString);
		}

		if (!isset($queryString['access_token'])) {
			$queryString['access_token'] = (string) $token;
		}

		$url = http_build_url($url, [
			'query' => http_build_query($queryString),
		]);

		return $this->createRequest($method, $url, null, $options);
	}

	/**
	 * Get the default scopes used by this provider.
	 *
	 * This should not be a complete list of all scopes, but the minimum
	 * required for the provider user interface!
	 *
	 * @return array
	 */
	protected function getDefaultScopes()
	{
		return $this->defaultScopes;
	}

	/**
	 * Check a provider response for errors.
	 *
	 * @link   https://instagram.com/developer/endpoints/
	 *
	 * @param  ResponseInterface $response
	 * @param  string            $data Parsed response data
	 *
	 * @return void
	 * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
	 */
	protected function checkResponse(ResponseInterface $response, $data)
	{
		// Standard error response format
		if (!empty($data['meta']['error_type'])) {
			throw InstagramFacebookIdentityProviderException::clientException($response, $data);
		}

		// OAuthException error response format
		if (!empty($data['error_type'])) {
			throw InstagramFacebookIdentityProviderException::oauthException($response, $data);
		}
	}

	public function getAccessToken($grant, array $options = []) {
		$token = parent::getAccessToken( $grant, $options );

        $token = $this->getLongLivedAccessToken($token);

		return $token;
	}

	protected function getLongLivedAccessToken( $token ) {
		$grant = $this->verifyGrant('ig_exchange_token');

		$params = [
			'client_secret' => $this->clientSecret,
			'access_token'  => $token->getToken(),
		];

        $params   = $grant->prepareRequestParameters($params, []);
		$request  = $this->getLongLivedAccessTokenRequest($params);
		$response = $this->getParsedResponse($request);
		if (false === is_array($response)) {
			throw new UnexpectedValueException(
				'Invalid response received from Authorization Server. Expected JSON.'
			);
		}
		$response['values']        = $token->getValues();
		$response['refresh_token'] = $response['access_token'];

		$prepared = $this->prepareAccessTokenResponse($response);
		$token    = $this->createAccessToken($prepared, $grant);

		return $token;
	}

	/**
	 * Returns a prepared request for requesting an access token.
	 *
	 * @param array $params Query string parameters
	 * @return RequestInterface
	 */
	protected function getLongLivedAccessTokenRequest(array $params)
	{
		$method  = self::METHOD_GET;
		$url     = $this->getBaseLongLivedAccessTokenUrl($params);
		$options = $this->optionProvider->getAccessTokenOptions($this->getAccessTokenMethod(), $params);

		return $this->getRequest($method, $url, $options);
	}

	/**
	 * Returns a prepared request for requesting an access token.
	 *
	 * @param array $params Query string parameters
	 * @return RequestInterface
	 */
	protected function geRefreshAccessTokenRequest(array $params)
	{
		$method  = self::METHOD_GET;
		$url     = $this->getRefreshAccessTokenUrl($params);
		$options = $this->optionProvider->getAccessTokenOptions($this->getAccessTokenMethod(), $params);

		return $this->getRequest($method, $url, $options);
	}

    public function getRefreshAccessToken( $token ) {
        $grant = $this->verifyGrant('ig_refresh_token');

        $params = [
            'access_token'  => $token,
        ];

        $params   = $grant->prepareRequestParameters($params, []);
        $request  = $this->geRefreshAccessTokenRequest($params);
        $response = $this->getParsedResponse($request);
        if (false === is_array($response)) {
            throw new UnexpectedValueException(
                'Invalid response received from Authorization Server. Expected JSON.'
            );
        }
        $response['refresh_token'] = $response['access_token'];

        $prepared = $this->prepareAccessTokenResponse($response);
        $token    = $this->createAccessToken($prepared, $grant);

        return $token;
    }

	/**
	 * Generate a user object from a successful user details request.
	 *
	 * @param array $response
	 * @param AccessToken $token
	 * @return ResourceOwnerInterface
	 */
	protected function createResourceOwner(array $response, AccessToken $token)
	{
		return new InstagramFacebookResourceOwner($response);
	}

	/**
	 * Sets host.
	 *
	 * @param string $host
	 *
	 * @return string
	 */
	public function setHost($host)
	{
		$this->host = $host;

		return $this;
	}
}