<?php

require_once 'vendor/autoload.php';

use Httpful\Request;

function authorize() {
	$url = 'https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token';
	$scopeEmulator = BOT_CLIENT_ID . '/.default';
	$scopeLive = 'https://api.botframework.com/.default';
	$scope = $scopeLive;
	$params = array(
		'grant_type' => 'client_credentials',
		'client_id' => BOT_CLIENT_ID,
		'client_secret' => BOT_CLIENT_SECRET,
		'scope' => $scope,
	);
	$response = Request::post($url)
		->body(http_build_query($params))
		->expectsJson()
		->send();
	return json_decode($response);
}

function retrieve_key_list() {
	$urlLive = 'https://login.botframework.com/v1/.well-known/openidconfiguration';
	$urlEmulator = 'https://login.microsoftonline.com/botframework.com/v2.0/.well-known/openid-configuration';
	$url = $urlLive;
	$response = Request::get($url)
		->expectsJson()
		->send();
	$endpoints = json_decode($response);

	$url = $endpoints->jwks_uri;
	$response = Request::get($url)
		->expectsJson()
		->send();
	return json_decode($response, true);
}

/**
 * Get hearder Authorization
 * */
function get_authorization_header() {
  $headers = null;
  if (isset($_SERVER['Authorization'])) {
	  $headers = trim($_SERVER["Authorization"]);
  }
  else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
    $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
  } elseif (function_exists('apache_request_headers')) {
    $requestHeaders = apache_request_headers();
    // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
    $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
    //print_r($requestHeaders);
    if (isset($requestHeaders['Authorization'])) {
        $headers = trim($requestHeaders['Authorization']);
    }
  }
  return $headers;
}
/**
 * get access token from header
 * */
function get_bearer_token() {
    $headers = get_authorization_header();
    // HEADER: Get the access token from the header
    if (!empty($headers)) {
        if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
            return $matches[1];
        }
    }
    return null;
}


/**
 *
 * 1. The token was sent in the HTTP Authorization header with "Bearer" scheme.
 * 2. The token is valid JSON that conforms to the JWT standard.
 * 3. The token contains an "issuer" claim with value of
 * 		https://sts.windows.net/d6d49420-f39b-4df7-a1dc-d59a935871db/.
 * 4. The token contains an "audience" claim with a value equal to the bot's
 * 		Microsoft App ID.
 * 5. The token contains an "appid" claim with the value equal to the
 * 		bot's Microsoft App ID.
 * 6. The token has not yet expired. Industry-standard clock-skew is 5
 * 		minutes.
 * 7.	The token has a valid cryptographic signature with a key listed in
 * 		the OpenID keys document that was retrieved in Step 3.
 */
function received_token_is_valid($token) {
	$token_valid = false;

	$token_arr = explode('.', $token);

	if (sizeof($token_arr) < 3) {
		trigger_error('Invalid token: '.$token, E_USER_ERROR);
	}


	$headers_enc = $token_arr[0];
	$claims_enc = $token_arr[1];
	$sig_enc = $token_arr[2];

	$headers_arr = json_decode(base64_url_decode($headers_enc), TRUE);
	$claims_arr = json_decode(base64_url_decode($claims_enc), TRUE);
	$sig = base64_url_decode($sig_enc);

	// The token contains an "issuer" claim with value of
	// https://sts.windows.net/d6d49420-f39b-4df7-a1dc-d59a935871db/.
	if ($claims_arr['iss'] != 'https://sts.windows.net/d6d49420-f39b-4df7-a1dc-d59a935871db/') {
		record('invalid issuer: '.$claims_arr['iss']);
		return false;
	}

	// The token contains an "audience" claim with a value equal to the bot's
	// Microsoft App ID.
	if ($claims_arr['aud'] != BOT_CLIENT_ID) {
		record('invalid audience');
		return false;
	}

	// The token contains an "appid" claim with the value equal to the
 	// bot's Microsoft App ID.
	if ($claims_arr['appid'] != BOT_CLIENT_ID) {
		record("invalid appid");
		return false;
	}

	// The token has not yet expired. Industry-standard clock-skew is 5
	// minutes.
	if ($claims_arr['exp'] - 150 < time() + 150) {
		record("timestamp expired");
		return false;
	}

	// The token has a valid cryptographic signature with a key listed in
  // the OpenID keys document that was retrieved in Step 3.
	$keylist_arr = retrieve_key_list();

	foreach($keylist_arr['keys'] as $key => $value) {
	  // select one key (which matches)
	  if($value['kid'] == $headers_arr['kid']) {

	    // get public key from key info
	    $cert_txt = '-----BEGIN CERTIFICATE-----' . "\n" . chunk_split($value['x5c'][0], 64) . '-----END CERTIFICATE-----';
	    $cert_obj = openssl_x509_read($cert_txt);
	    $pkey_obj = openssl_pkey_get_public($cert_obj);
	    $pkey_arr = openssl_pkey_get_details($pkey_obj);
	    $pkey_txt = $pkey_arr['key'];

	    // verify signature
	    $token_valid = openssl_verify($headers_enc . '.' . $claims_enc, $sig, $pkey_txt, OPENSSL_ALGO_SHA256);
	  }
	}

	// show result
	return $token_valid;
}

// Helper functions
function base64_url_decode($arg) {
  $res = $arg;
  $res = str_replace('-', '+', $res);
  $res = str_replace('_', '/', $res);
  switch (strlen($res) % 4) {
    case 0:
    break;
    case 2:
    $res .= "==";
    break;
    case 3:
    $res .= "=";
    break;
    default:
    break;
  }
  $res = base64_decode($res);
  return $res;
}

function record($msg) {
	file_put_contents('log.txt', $msg);
}

function qna_api_create_knowledge_base($name) {
	$url = 'https://westus.api.cognitive.microsoft.com/qnamaker/v2.0/knowledgebases/create';
	$json = json_encode(array('name' => $name));
	$response = Request::post($url)
		->addHeader('Ocp-Apim-Subscription-Key', QNA_SUBSCRIPTION_KEY)
		->addHeader('Content-Type', 'application/json')
		->expectsJson()
		->body($json)
		->sendsJson()
		->send();
	return $response->body->kbId;
}

function qna_api_delete_knowledge_base($kbId) {
	$url = 'https://westus.api.cognitive.microsoft.com/qnamaker/v2.0/knowledgebases/'.$kbId;
	$response = Request::delete($url)
		->addHeader('Ocp-Apim-Subscription-Key', QNA_SUBSCRIPTION_KEY)
		->send();
}

/**
 * @param array $add 		An array of question/answer pairs
 * @param array $delete An array of question/answer pairs
 */
function qna_api_update_knowledge_base($kbId, array $add=array(), array $delete=array()) {
	$url = 'https://westus.api.cognitive.microsoft.com/qnamaker/v2.0/knowledgebases/'.$kbId;
	$json_arr = array();
	if (sizeof($add) > 0) {
		$json_arr['add']['qnaPairs'] = $add;
	}
	if (sizeof($delete) > 0) {
		$json_arr['delete']['qnaPairs'] = $delete;
	}
	$json = json_encode($json_arr);
	$response = Request::patch($url)
		->addHeader('Ocp-Apim-Subscription-Key', QNA_SUBSCRIPTION_KEY)
		->addHeader('Content-Type', 'application/json')
		->body($json)
		->send();
}

function qna_api_publish_knowledge_base($kbId) {
	$url = 'https://westus.api.cognitive.microsoft.com/qnamaker/v2.0/knowledgebases/'.$kbId;
	$response = Request::put($url)
		->addHeader('Ocp-Apim-Subscription-Key', QNA_SUBSCRIPTION_KEY)
		->send();
}

/**
 * @param $feedbackRecords array
 *
 * array(
 * 	array(
 * 		'userId' => 1,
 * 		'userQuestion' => 'hey',
 * 		'kbQuestion' => 'hi',
 * 		'kbAnswer' => 'hey'
 * 	),
 * 	array(), ...
 * )
 */
function qna_api_train_knowledge_base($kbId, $feedbackRecords) {
	$url = 'https://westus.api.cognitive.microsoft.com/qnamaker/v2.0/knowledgebases/'.$kbId . '/train';
	$json = json_encode(array('feedbackRecords' => $feedbackRecords));
	$response = Request::patch($url)
		->addHeader('Ocp-Apim-Subscription-Key', QNA_SUBSCRIPTION_KEY)
		->addHeader('Content-Type', 'application/json')
		->body($json)
		->send();
}

function qna_api_generate_answer($kbId, $question) {
	$url = 'https://westus.api.cognitive.microsoft.com/qnamaker/v2.0/knowledgebases/'.$kbId.'/generateAnswer';
	$json = json_encode(array('question' => $question));
	$response = Request::post($url)
		->addHeader('Ocp-Apim-Subscription-Key', QNA_SUBSCRIPTION_KEY)
		->addHeader('Content-Type', 'application/json')
		->body($json)
		->send();
	return $response->body->answers[0]->answer;
}