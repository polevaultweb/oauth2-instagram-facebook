<?php

namespace League\OAuth2\Client\Provider\Exception;

use Psr\Http\Message\ResponseInterface;

class InstagramFacebookIdentityProviderException extends IdentityProviderException
{

	/**
	 * Creates client exception from response.
	 *
	 * @param  ResponseInterface $response
	 * @param  array             $data Parsed response data
	 *
	 * @return IdentityProviderException
	 */
	public static function clientException( ResponseInterface $response, $data )
	{
		$message = $response->getReasonPhrase();
		$code    = $response->getStatusCode();
		$body    = (string) $response->getBody();

		if ( isset( $data['error'], $data['error']['message'] ) ) {
			$message = (isset( $data['error']['type'] ) ? $data['error']['type'] . ': ' : '' ) . $data['error']['message'];
		}
		if ( isset( $data['error'], $data['error']['code'] ) ) {
			$code = $data['error']['code'];
		}

		return new static( $message, $code, $body );
	}

	/**
	 * Creates oauth exception from response.
	 *
	 * @param  ResponseInterface $response
	 * @param  array $data Parsed response data
	 *
	 * @return IdentityProviderException
	 */
	public static function oauthException(ResponseInterface $response, $data)
	{
		$message = $response->getReasonPhrase();
		$code = $response->getStatusCode();
		$body = (string) $response->getBody();

		if (isset($data['error_message'])) {
			$message = (isset( $data['error_type'] ) ? $data['error_type'] . ': ' : '' ) . $data['error_message'];
		}
		if (isset($data['code'])) {
			$code = $data['code'];
		}

		return new static($message, $code, $body);
	}
}