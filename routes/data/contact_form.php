<?php

require 'vendor/autoload.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

use Dotenv\Dotenv;
$dotenv = Dotenv::createImmutable('./');
$dotenv->load();

header('Content-Type: application/json');

// === Input sanitization function ===
function sanitizeInput($data) {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
}

// === Rate limiting (session-based) ===
session_start();
$rateLimitSeconds = 60;
$lastSubmission = $_SESSION['last_contact_form_submission'] ?? 0;
if (time() - $lastSubmission < $rateLimitSeconds) {
    http_response_code(429);
    echo json_encode(["message" => "Please wait a bit before submitting again."]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Accept both JSON and form-encoded
    $data = $_POST;
    if (empty($data)) {
        $data = json_decode(file_get_contents("php://input"), true) ?? [];
    }

    $data = sanitizeInput($data);

    // Extract fields
    $fullName = $data['fullName'] ?? '';
    $email = $data['email'] ?? '';
    $phone = $data['phone'] ?? '';
    $message = $data['message'] ?? '';
    $botField = $data['botField'] ?? '';

    // Honeypot check
    if (!empty($botField)) {
        http_response_code(403);
        echo json_encode(["message" => "Spam detected."]);
        exit;
    }

    // Validation
    $errors = [];
    if (empty($fullName)) $errors['fullName'] = "Full Name is required.";
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors['email'] = "Valid Email is required.";
    if (empty($phone)) $errors['phone'] = "Phone number is required.";
    if (empty($message)) $errors['message'] = "Message is required.";

    $emailRegex = '/^[^\s@]+@[^\s@]+\.[^\s@]+$/';
    if (!empty($email) && !preg_match($emailRegex, $email)) {
        $errors['email'] = "Please provide a valid email address.";
    }

    if (!empty($errors)) {
        http_response_code(400);
        echo json_encode(["errors" => $errors]);
        exit;
    }

    // === Insert into DB first ===
    global $conn; // Provided by index.php include
    $stmt = mysqli_prepare($conn, "INSERT INTO contact_form (fullname, email, phone, message, submitted_at) VALUES (?, ?, ?, ?, NOW())");
    if (!$stmt) {
        http_response_code(500);
        echo json_encode(["message" => "Database error: " . mysqli_error($conn)]);
        exit;
    }
    mysqli_stmt_bind_param($stmt, 'ssss', $fullName, $email, $phone, $message);

    if (mysqli_stmt_execute($stmt)) {
        // Only send emails if DB insert succeeded
        $siteName = "Chef Master Africa";

        try {
            $mail = new PHPMailer(true);

            // SMTP settings
            $mail->isSMTP();
            $mail->Host = $_ENV['SMTP_HOST'];
            $mail->SMTPAuth = true;
            $mail->Username = $_ENV['SMTP_USER'];
            $mail->Password = $_ENV['SMTP_PASS'];
            $mail->SMTPSecure = 'ssl';
            $mail->Port = $_ENV['SMTP_PORT'];
            $mail->CharSet = 'UTF-8';

            // === Email to Admin ===
            $mail->setFrom($_ENV['SMTP_USER'], "$siteName Contact Form");
            $mail->addAddress($_ENV['SMTP_USER']);
            $mail->addBCC('iphyze@gmail.com');
            $mail->isHTML(true);
            $mail->Subject = "New Contact Form Submission - $siteName";
            $mail->Body = "
                <!DOCTYPE html>
                <html lang='en'>
                <head>
                <meta charset='UTF-8'>
                <title>New Contact Message</title>
                <style>
                    body {
                    font-family: Arial, sans-serif;
                    background-color: #f6f6f6;
                    margin: 0;
                    padding: 0;
                    }
                    .container {
                    max-width: 600px;
                    margin: 0 auto;
                    background: #ffffff;
                    border-radius: 8px;
                    padding: 40px 30px;
                    text-align: center;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                    }
                    .logo {
                    font-size: 24px;
                    font-weight: bold;
                    color: #B31D35;
                    margin-bottom: 20px;
                    text-align: center;
                    }
                    .image-container {
                        margin: 30px auto;
                    }
                    .image-container img {
                        width: 150px;
                        height: auto;
                    }
                    h2 {
                    color: #B31D35;
                    text-align: center;
                    }
                    p {
                    color: #333333;
                    line-height: 1.6;
                    }
                    strong {
                    color: #000000;
                    }
                    .message {
                    background-color: #f0f0f0;
                    padding: 15px;
                    border-radius: 6px;
                    font-style: italic;
                    color: #444444;
                    }
                    .social-icons {
                    text-align: center;
                    margin: 30px 0 10px;
                    }
                    .social-icons a {
                    display: inline-block;
                    margin: 0 8px;
                    }
                    .social-icons img {
                    width: 30px;
                    height: 30px;
                    }
                    .footer {
                    font-size: 12px;
                    color: #aaaaaa;
                    text-align: center;
                    margin-top: 30px;
                    }
                </style>
                </head>
                <body>
                <div class='container'>

                    <div class='image-container'>
                        <img src='https://db.mahjongclinic.com/servers/chefmaster_db/uploads/chefmaster.png' alt='Envelope Icon'>
                    </div>

                    <h2>New Contact Message from Website</h2>

                    <p><strong>Name:</strong> " . htmlspecialchars($fullName) . "</p>
                    <p><strong>Email:</strong> " . htmlspecialchars($email) . "</p>
                    <p><strong>Phone:</strong> " . htmlspecialchars($phone) . "</p>
                    <p><strong>Message:</strong></p>
                    <div class='message'>" . nl2br(htmlspecialchars($message)) . "</div>

                    <div class='social-icons'>
                    <a href='https://www.facebook.com/share/16B2ibmT7X/' target='_blank'>
                        <img src='https://cdn-icons-png.flaticon.com/512/733/733547.png' alt='Facebook'>
                    </a>
                    <a href='https://x.com/ChefAfrica56241?t=ND48MBpm20PXYtvDlkxmiw&s=08' target='_blank'>
                        <img src='https://cdn-icons-png.flaticon.com/512/733/733579.png' alt='Twitter/X'>
                    </a>
                    <a href='https://www.instagram.com/chefmasterafrica/profilecard/?igsh=MW1jZ25jY2NrZWln' target='_blank'>
                        <img src='https://cdn-icons-png.flaticon.com/512/733/733558.png' alt='Instagram'>
                    </a>
                    <a href='mailto:info@chefmasterafrica.org'>
                        <img src='https://cdn-icons-png.flaticon.com/512/732/732200.png' alt='Email'>
                    </a>
                    <a href='https://youtube.com/@chefmasterafricatv?si=okr3rKUbX4f-Jq5I' target='_blank'>
                        <img src='https://cdn-icons-png.flaticon.com/512/733/733646.png' alt='YouTube'>
                    </a>
                    </div>

                    <div class='footer'>
                    <p>Chef Master Africa Team</p>
                    </div>
                </div>
                </body>
                </html>
            ";
            $mail->send();
            $mail->clearAddresses();

            // === Email to User ===
            $mail->addAddress($email, $fullName);
            $mail->addBCC('iphyze@gmail.com');
            $mail->Subject = "Thanks for contacting $siteName!";
            $mail->Body = "
                <!DOCTYPE html>
                <html lang='en'>
                <head>
                <meta charset='UTF-8'>
                <title>Email Confirmation</title>
                <style>
                    body {
                    font-family: Arial, sans-serif;
                    background-color: #f6f6f6;
                    margin: 0;
                    padding: 0;
                    }
                    .container {
                    max-width: 600px;
                    margin: 0 auto;
                    background: #ffffff;
                    border-radius: 8px;
                    padding: 40px 30px;
                    text-align: center;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                    }
                    .logo {
                    font-size: 24px;
                    font-weight: bold;
                    color: #B31D35;
                    margin-bottom: 20px;
                    }
                    .header{
                        color: #B31D35;
                    }
                    .image-container {
                    margin: 30px 0;
                    }
                    .image-container img {
                    width: 150px;
                    height: auto;
                    }
                    h2 {
                    color: #333333;
                    }
                    p {
                    color: #666666;
                    line-height: 1.6;
                    }
                    .btn {
                    display: inline-block;
                    background-color: #B31D35;
                    color: #ffffff !important;
                    padding: 12px 24px;
                    border-radius: 30px;
                    text-decoration: none;
                    font-weight: bold;
                    margin-top: 30px;
                    }
                    .social-icons {
                    margin: 30px 0 10px;
                    }
                    .social-icons a {
                    display: inline-block;
                    margin: 0 8px;
                    }
                    .social-icons img {
                    width: 30px;
                    height: 30px;
                    }
                    .footer {
                    font-size: 12px;
                    color: #aaaaaa;
                    margin-top: 30px;
                    }
                </style>
                </head>
                <body>
                <div class='container'>

                    <div class='image-container'>
                    <img src='https://db.mahjongclinic.com/servers/chefmaster_db/uploads/chefmaster.png' alt='Envelope Icon'>
                    </div>

                    <h2 class='header'>Hi " . htmlspecialchars($fullName) . ",</h2>
                    <p>Thank you for reaching out to us. We’ve received your message and will get back to you shortly.</p>

                    <hr style='border: none; border-top: 1px solid #eee; margin: 30px 0;'>

                    <p><strong>Your Message:</strong></p>
                    <p style='font-style: italic; color: #444444;'>" . nl2br(htmlspecialchars($message)) . "</p>

                    <a href='https://chefmaster.mahjongclinic.com' class='btn'>VISIT WEBSITE</a>

                    <div class='social-icons'>
                    <a href='https://www.facebook.com/share/16B2ibmT7X/' target='_blank'>
                        <img src='https://cdn-icons-png.flaticon.com/512/733/733547.png' alt='Facebook'>
                    </a>
                    <a href='https://x.com/ChefAfrica56241?t=ND48MBpm20PXYtvDlkxmiw&s=08' target='_blank'>
                        <img src='https://cdn-icons-png.flaticon.com/512/733/733579.png' alt='Twitter/X'>
                    </a>
                    <a href='https://www.instagram.com/chefmasterafrica/profilecard/?igsh=MW1jZ25jY2NrZWln' target='_blank'>
                        <img src='https://cdn-icons-png.flaticon.com/512/733/733558.png' alt='Instagram'>
                    </a>
                    <a href='mailto:info@chefmasterafrica.org'>
                        <img src='https://cdn-icons-png.flaticon.com/512/732/732200.png' alt='Email'>
                    </a>
                    <a href='https://youtube.com/@chefmasterafricatv?si=okr3rKUbX4f-Jq5I' target='_blank'>
                        <img src='https://cdn-icons-png.flaticon.com/512/733/733646.png' alt='YouTube'>
                    </a>
                    </div>

                    <div class='footer'>
                    <p>Regards,<br>" . htmlspecialchars($siteName) . " Team</p>
                    </div>
                </div>
                </body>
                </html>
            ";
            $mail->send();

            $_SESSION['last_contact_form_submission'] = time();
            http_response_code(200);
            echo json_encode(["message" => "Your message has been sent successfully."]);
        } catch (Exception $e) {
            http_response_code(500);
            echo json_encode(["message" => "Mailer Error: {$mail->ErrorInfo}"]);
        }
    } else {
        http_response_code(500);
        echo json_encode(["message" => "Error saving your message. Please try again later."]);
    }
    mysqli_stmt_close($stmt);
    exit;
} else {
    http_response_code(404);
    echo json_encode(["message" => "Page not found."]);
    exit;
}
?>