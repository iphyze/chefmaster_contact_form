<?php
// List of routes that require token verification
$protectedRoutes = [
    '/metaccord/db/update',
    // '/metaccord/db/register',
];

// Get the current request URI and method
$requestUri = $_SERVER['REQUEST_URI'];
$requestMethod = $_SERVER['REQUEST_METHOD'];

// Function to verify token
function verifyToken() {
    // Get the authorization header
    // $headers = apache_request_headers();
    $headers = getallheaders();
    // $authHeader = $headers['Authorization'] ?? '';
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';


    if (!$authHeader) {
        http_response_code(401); // Unauthorized
        echo json_encode(["message" => "Authorization header not found!"]);
        exit;
    }

    // Extract the token from the header
    list($jwt) = sscanf($authHeader, 'Bearer %s');

    if (!$jwt) {
        http_response_code(401); // Unauthorized
        echo json_encode(["message" => "Token not found."]);
        exit;
    }

    // Decode the token
    $secretKey = 'your_secret_key'; // Use the same secret key used during token creation
    list($header, $payload, $signature) = explode('.', $jwt);

    // Verify signature
    $expectedSignature = base64UrlEncode(hash_hmac('SHA256', "$header.$payload", $secretKey, true));

    if ($signature !== $expectedSignature) {
        http_response_code(401); // Unauthorized
        echo json_encode(["message" => "Invalid token."]);
        exit;
    }

    // Decode payload
    $decodedPayload = json_decode(base64UrlDecode($payload), true);

    if (isset($decodedPayload['exp']) && $decodedPayload['exp'] < time()) {
        http_response_code(401); // Unauthorized
        echo json_encode(["message" => "Token has expired."]);
        exit;
    }

    // Optionally: You can attach the user info to the request if needed
    $_SESSION['user_id'] = $decodedPayload['id'];
}

// Function to handle Base64 URL decoding
function base64UrlDecode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $data .= substr('====', $remainder);
    }
    return base64_decode(strtr($data, '-_', '+/'));
}

// Function to handle Base64 URL encoding
function base64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// Check if the route exists in the protected routes list
function routeExists($requestUri, $protectedRoutes) {
    foreach ($protectedRoutes as $route) {
        // Check if the route partially matches (for routes with dynamic segments)
        if (strpos($requestUri, $route) === 0) {
            return true;
        }
    }
    return false;
}

// Handle route checking
if (routeExists($requestUri, $protectedRoutes)) {
    // If the route exists and requires token, verify token
    verifyToken();

    // Route-specific logic goes here (for example, updating user data)
    // You can call your other logic depending on the route and method
} else {
    // If the route does not exist, show "Route not found"
    http_response_code(404); // Not Found
    echo json_encode(["message" => "page not found."]);
    exit;
}
?>
