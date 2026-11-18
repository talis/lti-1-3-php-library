<?php
/**
 * Stub platform key set server (built-in server router) for LTI_Message_Launch_Key_Set_Test.
 * Rejects HTTP/1.0 with 426.
 */

if ($_SERVER['SERVER_PROTOCOL'] === 'HTTP/1.0') {
    http_response_code(426);
    header('Content-Type: text/plain');
    echo 'Upgrade Required';
    return true;
}

switch (parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)) {
    case '/certs':
        $public_key = file_get_contents(__DIR__ . '/../fixtures/private.pub');
        $details = openssl_pkey_get_details(openssl_pkey_get_public($public_key));
        $base64url = function ($data) {
            return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
        };
        header('Content-Type: application/json');
        echo json_encode([
            'keys' => [[
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'kid' => 'test-kid',
                'n' => $base64url($details['rsa']['n']),
                'e' => $base64url($details['rsa']['e']),
            ]],
        ]);
        return true;
    case '/redirect-to-certs':
        header('Location: /certs', true, 302);
        return true;
    case '/redirect-to-server-error':
        header('Location: /server-error', true, 302);
        return true;
    case '/server-error':
        http_response_code(500);
        echo json_encode(['keys' => []]);
        return true;
    case '/not-json':
        header('Content-Type: text/html');
        echo '<html>Not a key set</html>';
        return true;
    default:
        http_response_code(404);
        echo 'Not Found';
        return true;
}
