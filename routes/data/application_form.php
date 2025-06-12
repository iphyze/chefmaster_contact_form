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
    $state_of_origin = $data['state_of_origin'] ?? '';
    $phone = $data['phone'] ?? '';
    $email = $data['email'] ?? '';
    $address = $data['address'] ?? '';
    $city = $data['city'] ?? '';
    $state = $data['state'] ?? '';
    $zip_code = $data['zip_code'] ?? '';
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
    $city_emergency = $data['city_emergency'] ?? '';
    $state_emergency = $data['state_emergency'] ?? '';
    $zip_code_emergency = $data['zip_code_emergency'] ?? '';
    $competition_knowledge = $data['competition_knowledge'] ?? '';
    $passport_image_url = '';
    $signature_image_url = '';
    $additional_comments = $data['additional_comments'] ?? '';
    $botField = $data['botField'] ?? '';
    $allowed_types = ['image/jpeg', 'image/png', 'image/jpg'];
    $max_size = 5 * 1024 * 1024; // 5MB


    // Ensure both passport_image and signature_image are uploaded and not empty
    foreach (['passport_image', 'signature_image'] as $img_field) {
        if (
            !isset($_FILES[$img_field]) ||
            empty($_FILES[$img_field]['name']) ||
            $_FILES[$img_field]['error'] === UPLOAD_ERR_NO_FILE
        ) {
            http_response_code(400);
            echo json_encode(["message" => ucfirst(str_replace('_', ' ', $img_field)) . " is required."]);
            exit;
        }
    }


    foreach (['passport_image', 'signature_image'] as $img_field) {
        // if (empty($_FILES[$img_field]['name']) || $_FILES[$img_field]['error'] === UPLOAD_ERR_NO_FILE) {
        //     http_response_code(400);
        //     echo json_encode(["message" => ucfirst(str_replace('_', ' ', $img_field)) . " is required."]);
        //     exit;
        // }
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
    if (empty($dob)) $errors['dob'] = "Date of Birth is required.";
    if (empty($gender)) $errors['gender'] = "Gender is required.";
    if (empty($state_of_origin)) $errors['state_of_origin'] = "State of Origin is required.";
    if (empty($phone)) $errors['phone'] = "Phone number is required.";
    if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors['email'] = "Valid Email is required.";
    if (empty($address)) $errors['address'] = "Address is required.";
    if (empty($city)) $errors['city'] = "City is required.";
    if (empty($state)) $errors['state'] = "State is required.";
    if (empty($zip_code)) $errors['zip_code'] = "Zip code is required.";
    if (empty($occupation)) $errors['occupation'] = "Occupation is required.";
    if (empty($years_of_experience)) $errors['years_of_experience'] = "Years of experience is required.";
    if (empty($culinary_training)) $errors['culinary_training'] = "Culinary training is required.";
    if (empty($degree)) $errors['degree'] = "Degree is required.";
    if (empty($graduation_year)) $errors['graduation_year'] = "Graduation year is required.";
    if (empty($specialized_category)) $errors['specialized_category'] = "Specialized category is required.";
    if (empty($food_allergies)) $errors['food_allergies'] = "Food allergies field is required.";
    if (empty($signature_dish)) $errors['signature_dish'] = "Signature dish is required.";
    if (empty($signature_dish_description)) $errors['signature_dish_description'] = "Signature dish description is required.";
    if (empty($participation_reason)) $errors['participation_reason'] = "Reason for participation is required.";
    if (empty($fullName_emergency_contact)) $errors['fullName_emergency_contact'] = "Emergency contact name is required.";
    if (empty($relationship)) $errors['relationship'] = "Relationship with emergency contact is required.";
    if (empty($phone_emergency)) $errors['phone_emergency'] = "Emergency contact phone number is required.";
    if (empty($address_emergency)) $errors['address_emergency'] = "Emergency contact address is required.";
    if (empty($city_emergency)) $errors['city_emergency'] = "Emergency contact city is required.";
    if (empty($state_emergency)) $errors['state_emergency'] = "Emergency contact state is required.";
    if (empty($zip_code_emergency)) $errors['zip_code_emergency'] = "Emergency contact zip code is required.";
    if (empty($competition_knowledge)) $errors['competition_knowledge'] = "How you heard about the competition is required.";


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
    $stmt = mysqli_prepare($conn, "
        INSERT INTO application_form (
            fullname, dob, gender, state_of_origin, phone, email, address, city, state, zip_code, occupation, years_of_experience, culinary_training, degree, graduation_year, specialized_category, food_allergies, signature_dish, signature_dish_description, participation_reason, fullName_emergency_contact, relationship, phone_emergency, address_emergency, city_emergency, state_emergency, zip_code_emergency, competition_knowledge, passport_image, signature_image, additional_comments, submitted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    ");

    if (!$stmt) {
        http_response_code(500);
        echo json_encode(["message" => "Database error: " . mysqli_error($conn)]);
        exit;
    }

    mysqli_stmt_bind_param(
        $stmt, 'sssssssssssssssssssssssssssssss',
        $fullName, $dob, $gender, $state_of_origin, $phone, $email, $address, $city,
        $state, $zip_code, $occupation, $years_of_experience, $culinary_training, $degree,
        $graduation_year, $specialized_category, $food_allergies, $signature_dish,
        $signature_dish_description, $participation_reason, $fullName_emergency_contact,
        $relationship, $phone_emergency, $address_emergency, $city_emergency, $state_emergency,
        $zip_code_emergency, $competition_knowledge, $passport_image_url, $signature_image_url,
        $additional_comments
    );


    $emailData = [
    'siteName' => 'Chef Master Africa',
    'fullName' => $fullName,
    'dob' => $dob,
    'gender' => $gender,
    'state_of_origin' => $state_of_origin,
    'email' => $email,
    'phone' => $phone,
    'address' => $address,
    'city' => $city,
    'state' => $state,
    'zip_code' => $zip_code,
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
    'city_emergency' => $city_emergency,
    'state_emergency' => $state_emergency,
    'zip_code_emergency' => $zip_code_emergency,
    'competition_knowledge' => $competition_knowledge,
    'passport_image_url' => $passport_image_url,
    'signature_image_url' => $signature_image_url,
    'additional_comments' => $additional_comments
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