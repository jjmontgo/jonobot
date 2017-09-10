<?php

include_once 'defines.php';
include_once 'functions.php';

use Httpful\Request;

// do I only do this if I want to initiate the interaction?
$authResponse = authorize();
$accessToken = $authResponse->access_token;

$token = get_bearer_token();
// if (!received_token_is_valid($token)) {
// 	header('HTTP/1.0 403 Forbidden', true, 403);
// 	exit();
// }

$request = json_decode(file_get_contents('php://input'), true);
// record(print_r($request, true));
header('HTTP/1.1 200 OK', true, 200);

if (!is_array($request) || $request['type'] != 'message') {
	exit();
}

$kbId = '93b2fcaa-2743-4bde-bd21-f7d86655bccb';
$answer = qna_api_generate_answer($kbId, $request['text']);

$reply = json_encode(array(
	'type' => 'message',
	'conversation' => $request['conversation'],
	'from' => $request['recipient'],
	'locale' => $request['locale'],
	'recipient' => $request['from'],
	'replyTold' => $request['id'],
	'text' => $answer,
	'textFormat' => 'plain',
));

$responseUrl = $request['serviceUrl'] . '/v3/conversations/' . $request['conversation']['id'] . '/activities/' . $request['id'];

try {
	$response = Request::post($responseUrl)
		->addHeader('Authorization', 'Bearer ' . $accessToken)
		->addHeader('Content-Type', 'application/json')
		->body($reply)
		->sendsJson()
		->send();
	record(print_r($response, true));
} catch (Exception $e) {
	// record('');
}