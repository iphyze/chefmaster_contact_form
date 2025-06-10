<?php

require 'vendor/autoload.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

use Dotenv\Dotenv;
$dotenv = Dotenv::createImmutable('./');
$dotenv->load();

require './utils/email_template.php';

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
    $dob = $data['dob'] ?? '';
    $gender = $data['gender'] ?? '';
    $email = $data['email'] ?? '';
    $phone = $data['phone'] ?? '';
    $address = $data['address'] ?? '';
    $occupation = $data['occupation'] ?? '';
    $years_of_experience = $data['years_of_experience'] ?? '';
    $culinary_training = $data['culinary_training'] ?? '';
    $degree = $data['degree'] ?? '';
    $graduation_year = $data['graduation_year'] ?? '';
    $specialized_category = $data['specialized_category'] ?? '';
    $food_allergies = $data['food_allergies'] ?? '';
    $signature_dish = $data['signature_dish'] ?? '';
    $signature_dish_description = $data['signature_dish_description'] ?? '';
    $participation_reason = $data['participation_reason'] ?? '';
    $fullName_emergency_contact = $data['fullName_emergency_contact'] ?? '';
    $relationship = $data['relationship'] ?? '';
    $phone_emergency = $data['phone_emergency'] ?? '';
    $address_emergency = $data['address_emergency'] ?? '';
    $botField = $data['botField'] ?? '';
    $passport_image_url = '';
    $signature_image_url = '';
    $allowed_types = ['image/jpeg', 'image/png', 'image/jpg'];
    $max_size = 5 * 1024 * 1024; // 5MB


    foreach (['passport_image', 'signature_image'] as $img_field) {
    if (isset($_FILES[$img_field]) && $_FILES[$img_field]['error'] === UPLOAD_ERR_OK) {
        $file = $_FILES[$img_field];
        if (!in_array($file['type'], $allowed_types)) {
            http_response_code(400);
            echo json_encode(["message" => ucfirst(str_replace('_', ' ', $img_field)) . " must be a JPG or PNG image."]);
            exit;
        }
        if ($file['size'] > $max_size) {
            http_response_code(400);
            echo json_encode(["message" => ucfirst(str_replace('_', ' ', $img_field)) . " must not exceed 5MB."]);
            exit;
        }
        $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
        $new_name = uniqid($img_field . '_') . '.' . $ext;
        $upload_dir = '../uploads/';
        if (!is_dir($upload_dir)) mkdir($upload_dir, 0777, true);
        $dest = $upload_dir . $new_name;
        if (move_uploaded_file($file['tmp_name'], $dest)) {
            $basePath = '/servers/chefmaster_db';
            $url = $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . $basePath . '/uploads/' . $new_name;
            if ($img_field === 'passport_image') $passport_image_url = $url;
            if ($img_field === 'signature_image') $signature_image_url = $url;
        } else {
            http_response_code(500);
            echo json_encode(["message" => "Failed to upload " . str_replace('_', ' ', $img_field)]);
            exit;
        }
    }
}



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
    $stmt = mysqli_prepare($conn, "INSERT INTO application_form (
    fullname, dob, gender, email, phone, address, occupation, years_of_experience, culinary_training, degree, graduation_year, specialized_category, food_allergies, signature_dish, signature_dish_description, participation_reason, fullName_emergency_contact, relationship, phone_emergency, address_emergency, passport_image, signature_image, submitted_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())");
    if (!$stmt) {
        http_response_code(500);
        echo json_encode(["message" => "Database error: " . mysqli_error($conn)]);
        exit;
    }
    mysqli_stmt_bind_param($stmt, 'ssssssssssssssssssssss',
    $fullName, $dob, $gender, $email, $phone, $address, $occupation, $years_of_experience, $culinary_training, $degree, $graduation_year, $specialized_category, $food_allergies, $signature_dish, $signature_dish_description, $participation_reason, $fullName_emergency_contact, $relationship, $phone_emergency, $address_emergency, $passport_image_url, $signature_image_url
    );


    $emailData = [
    'siteName' => 'Chef Master Africa',
    'fullName' => $fullName,
    'dob' => $dob,
    'gender' => $gender,
    'email' => $email,
    'phone' => $phone,
    'address' => $address,
    'occupation' => $occupation,
    'years_of_experience' => $years_of_experience,
    'culinary_training' => $culinary_training,
    'degree' => $degree,
    'graduation_year' => $graduation_year,
    'specialized_category' => $specialized_category,
    'food_allergies' => $food_allergies,
    'signature_dish' => $signature_dish,
    'signature_dish_description' => $signature_dish_description,
    'participation_reason' => $participation_reason,
    'fullName_emergency_contact' => $fullName_emergency_contact,
    'relationship' => $relationship,
    'phone_emergency' => $phone_emergency,
    'address_emergency' => $address_emergency,
    'passport_image_url' => $passport_image_url,
    'signature_image_url' => $signature_image_url
    ];


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
            $mail->setFrom($_ENV['SMTP_USER'], "$siteName Application Form");
            $mail->addAddress($_ENV['SMTP_USER']);
            $mail->addBCC('iphyze@gmail.com');
            $mail->isHTML(true);
            $mail->Subject = "New Application Form Submission - $siteName";
            // $mail->Body = getApplicationEmailBody($emailData, 'admin');
            $mail->Body = getAdminApplicationEmail($emailData);
            $mail->send();
            $mail->clearAddresses();

            // === Email to User ===
            $mail->addAddress($email, $fullName);
            $mail->addBCC('iphyze@gmail.com');
            $mail->Subject = "Thanks for contacting $siteName!";
            // $mail->Body = getApplicationEmailBody($emailData, 'user');
            $mail->Body = getUserApplicationEmail($emailData);
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