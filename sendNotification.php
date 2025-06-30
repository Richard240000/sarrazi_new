<?php
if ($_SERVER['REQUEST_METHOD'] !== 'GET' || !isset($_GET['title'], $_GET['body'])) {
    http_response_code(400);
    echo json_encode(['error' => 'title and body required']);
    exit;
}

$title = $_GET['title'];
$body = $_GET['body'];

$credentials = json_decode(file_get_contents(__DIR__ . '/firebase-credentials.json'), true);
if (!$credentials || !isset($credentials['client_email'], $credentials['private_key'])) {
    http_response_code(500);
    echo json_encode(['error' => 'Firebase credentials invalid']);
    exit;
}

$credentials['private_key'] = str_replace(["\n", "
"], "
", $credentials['private_key']);
$privateKey = openssl_pkey_get_private($credentials['private_key']);

if (!$privateKey) {
    http_response_code(500);
    echo json_encode(['error' => 'Invalid private key']);
    exit;
}

$now = time();
$header = ['alg' => 'RS256', 'typ' => 'JWT'];
$payload = [
    'iss' => $credentials['client_email'],
    'scope' => 'https://www.googleapis.com/auth/firebase.messaging',
    'aud' => 'https://oauth2.googleapis.com/token',
    'iat' => $now,
    'exp' => $now + 3600
];

function base64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

$jwtHeader = base64UrlEncode(json_encode($header));
$jwtPayload = base64UrlEncode(json_encode($payload));
$signatureInput = "$jwtHeader.$jwtPayload";

$signature = '';
openssl_sign($signatureInput, $signature, $privateKey, 'sha256');
$jwtSignature = base64UrlEncode($signature);
$jwt = "$signatureInput.$jwtSignature";

$tokenRequest = http_build_query([
    'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    'assertion' => $jwt
]);

$opts = ['http' => [
    'method'  => 'POST',
    'header'  => "Content-Type: application/x-www-form-urlencoded",
    'content' => $tokenRequest,
    'ignore_errors' => true
]];

$response = file_get_contents('https://oauth2.googleapis.com/token', false, stream_context_create($opts));
$result = json_decode($response, true);

if (empty($result['access_token'])) {
    http_response_code(500);
    echo json_encode(['error' => 'token error', 'details' => $result]);
    exit;
}

$accessToken = $result['access_token'];
$message = [
    'message' => [
        'topic' => 'all',
        'notification' => [
            'title' => $title,
            'body' => $body
        ]
    ]
];

$options = [
    'http' => [
        'method'  => 'POST',
        'header'  => [
            'Authorization: Bearer ' . $accessToken,
            'Content-Type: application/json'
        ],
        'content' => json_encode($message),
        'ignore_errors' => true
    ]
];

$response = file_get_contents('https://fcm.googleapis.com/v1/projects/sarrazi-connect/messages:send', false, stream_context_create($options));
echo $response;
