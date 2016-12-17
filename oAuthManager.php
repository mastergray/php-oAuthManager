<?php

/****

	Static class for making oAuth requests with cURL

****/

class oAuthManager {

	//	Authorization Credentials:

	private static $_consumer_key;
	private static  $_consumer_secret;
	private static $_oauth_access_token;
	private static $_oauth_access_token_secret;

	private static $_oAuth; 		// oAuth request parameters;
	private static $_URL; 		  	// URL that request is being sent to
	private static $_httpMethod;	// HTTP method for URL 
	
	private static $_http_code;		// Stores http header reponse after cURL request has been sent;
	private static $contentType;
	private static $_sentRequest;

/****

	STATIC SETTER METHODS

****/


	//	Sets consumer authorization credentials:

		public static function setConsumer($consumer_key, $consumer_secret) {
			
			self::$_consumer_key 	= $consumer_key;
			self::$_consumer_secret = $consumer_secret;
			
		}
	
	//	Sets token authorization credentials:
	
		public static function setToken($oauth_access_token, $oauth_access_token_secret) {
		
			self::$_oauth_access_token		  = $oauth_access_token;
			self::$_oauth_access_token_secret = $oauth_access_token_secret;
		
		}
	
	// Sets HTTP method, URL, and oAuth parameters (prior to generating signature):
	
		public static function setParams($httpMethod, $URL, $oAuthParams) {
			
			self::$_httpMethod = $httpMethod;
			self::$_URL 	   = $URL;
			self::$_oAuth 	   = $oAuthParams;
				
		}


/****

	STATIC GETTER METHODS

****/

	
	//	Returns set URL for use when declaring options of a cURL request:
	
		public static function getURL() {
		
			return self::$_URL;
		
		}

	
	//	Returns header for oAuth request:
	
		public static function getHeader() {
			
			//	Sets signature for oAuth request:
				
				$oauth_signature = self::buildSignature();
				
			//	Appends oAuth parameters with oAuth signature:
			
				self::$_oAuth['oauth_signature'] = $oauth_signature;
				
				ksort(self::$_oAuth);
				
			//	Generates header and returns request as array for cURL options:
			
			return self::buildHeader();
		}


		public static function getRequestInfo() {
		
			return self::$_sentRequest;
		
		}
/****

	STATIC cURL METHODS

****/	


 	//	Returns reponse from cURL AFTER parameters AND options have been set:

		public static function send($options) {
			
				$channel  = curl_init();
				curl_setopt_array($channel, $options);
				$response = curl_exec($channel);
				self::$_http_code = curl_getinfo($channel, CURLINFO_HTTP_CODE);	//	Stores header response for last sent cURL request
			//	self::$_sentRequest = curl_getinfo($channel, CURLINFO_HEADER_OUT);
				self::$contentType = curl_getinfo($channel, CURLINFO_CONTENT_TYPE);
				curl_close($channel);
	
			return $response;
		}
		
	//	Returns HTTP header response for last sent cURL request:
	
		public static function httpResponse() {
		
				if (!isset(self::$_http_code)) {
				
					self::$_http_code = NULL;
				
				}
			
			return self::$_http_code;
		
		}
		
		public static function getContentType() {
		
				if (!isset(self::$contentType)) {
				
					self::$contentType = NULL;
				
				}
			
			return self::$contentType;
		
		}
		
	// Parses oAuth request response into an associative array:
	
		public static function parseResponse ($response) {
			
			$result = array();
			$keys 	= explode('&', $response);
			
				while (count($keys) > 0) {
				
					$elem = explode('=', array_pop($keys), 2);
					$result[$elem[0]] = $elem[1];
				
				}
			
			return $result;
			
		}

/****

	Private oAuth Methods
	
****/


	//	Generates 'Parameter string' for building the 'base string' of an oAuth signature:

		private	static function buildParameterStr() {
		
				$sortedKeys = array();
					
					foreach(self::$_oAuth as $key=>$value) {
						
						array_push($sortedKeys, rawurlencode($key) . '=' . rawurlencode($value));
					}
				
				sort($sortedKeys);
				
			return implode('&', $sortedKeys);
		} 


	//	Generates 'base string' for building an oAuth signature:

		private	static function buildBaseStr () {
				
			return strtoupper(self::$_httpMethod) . '&' . rawurlencode(self::$_URL) . '&' . rawurlencode(self::buildParameterStr());		
		}
		
	//	Generates 'signing key' for oAuth signature:
	
		private	static function buildSigningKey () {
			
				$signingKey = rawurlencode(self::$_consumer_secret) . '&';
				
				//	For 'signing' a non-request token:
				
					if (isset(self::$_oauth_access_token_secret)) {
	
						$signingKey .= rawurlencode(self::$_oauth_access_token_secret);
					
					}
				
			return $signingKey;
		}

	//	Returns oAuth signature:

		private	static function buildSignature() {
				
			return base64_encode(hash_hmac('sha1', self::buildBaseStr() , self::buildSigningKey(), true));
				
		}
		
	//	Generates header for oAuth request:
		
		public	static function buildHeader() {
			
			$headers = array(); 
			
				foreach(self::$_oAuth as $key=>$value) {
				
					array_push($headers, $key . '="' . rawurlencode($value) . '"'); 
				
				}
			
			return 'Authorization: OAuth ' . implode(', ', $headers);
			 
		}
/****

	Public oAuth methods

****/

	// Matches baseStr and signature (from an API's  oAuth tool) to the result of set paramters and a secret token for debugging an oAuth request:

	public static function debug($baseStr, $signature, $secret, $httpMethod, $URL, $params) {
	
		self::$_oauth_access_token_secret = $secret;
	
		oAuthManager::setParams($httpMethod, $URL, $params);
		
		if (oAuthManager::buildBaseStr() == $baseStr) {
			
			echo '<p>Base String Success</p>';
			
		} else {
			
			echo '<p>Base String Fail: ' . oAuthManager::buildBaseStr() . '</p>';
			
		}
		
		if (oAuthManager::buildSignature() == $signature) {
		
			echo '<p>Signature Success</p>';
		
		} else {
		
			echo '<p>Signature Fail: </p>' . oAuthManager::buildSignature();
		
		}
		
	}
	
	public static function oAuthURL() {
		
			//	Sets signature for oAuth request:
				
				$oauth_signature = self::buildSignature();
				
			//	Appends oAuth parameters with oAuth signature:
			
				self::$_oAuth['oauth_signature'] = $oauth_signature;
				
				ksort(self::$_oAuth);
				
			//	Generates header and returns request as array for cURL options:
	
		return self::$_URL . '?' . http_build_query(self::$_oAuth);
	
	}
	
}

?>