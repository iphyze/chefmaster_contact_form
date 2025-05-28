
<?php

require 'vendor/autoload.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

header('Content-Type: application/json');


// Input sanitization function
function sanitizeInput($data) {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    return htmlspecialchars(strip_tags(trim($data)), ENT_QUOTES, 'UTF-8');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents("php://input"), true);

    // Sanitize all input data
    $data = sanitizeInput($data);

    // Extract all form fields
    $quality = $data['quality'] ?? null;
    $quality_comments = $data['quality_comments'] ?? null;
    $timeline = $data['timeline'] ?? null;
    $timeline_comments = $data['timeline_comments'] ?? null;
    $expertise = $data['expertise'] ?? null;
    $expertise_comments = $data['expertise_comments'] ?? null;
    $communication = $data['communication'] ?? null;
    $communication_comments = $data['communication_comments'] ?? null;
    $resolution = $data['resolution'] ?? null;
    $resolution_comments = $data['resolution_comments'] ?? null;
    $cleaniness = $data['cleaniness'] ?? null;
    $cleaniness_comments = $data['cleaniness_comments'] ?? null;
    $safety = $data['safety'] ?? null;
    $safety_comments = $data['safety_comments'] ?? null;
    $response = $data['response'] ?? null;
    $response_comments = $data['response_comments'] ?? null;
    $electrical_services = $data['electrical_services'] ?? null;
    $mechanical_services = $data['mechanical_services'] ?? null;
    $filled_by = $data['filled_by'] ?? null;
    $position = $data['position'] ?? null;
    $email = $data['email'] ?? null;
    $office_address = $data['office_address'] ?? null;
    $phone_number = $data['phone_number'] ?? null;
    $fax_number = $data['fax_number'] ?? null;
    $project_title = $data['project_title'] ?? null;
    $company = $data['company'] ?? null;
    $location = $data['location'] ?? null;

    // Required fields validation
    $requiredFields = [
        'quality' => 'Please fill in the quality rating!',
        'timeline' => 'Please fill in the timeline rating!',
        'expertise' => 'Please fill in the expertise rating!',
        'communication' => 'Please fill in the communication rating!',
        'resolution' => 'Please fill in the resolution rating!',
        'cleaniness' => 'Please fill in the cleaniness rating!',
        'safety' => 'Please fill in the safety rating!',
        'response' => 'Please fill in the response rating!',
        'electrical_services' => 'Please fill in the electrical services rating!',
        'mechanical_services' => 'Please fill in the mechanical services rating!',
        'filled_by' => 'Please provide your name',
        // 'position' => 'Please provide your position',
        'office_address' => 'Please provide your office address',
        'phone_number' => 'Please provide your phone number',
        // 'fax_number' => 'Please provide your fax number',
        'project_title' => 'Please provide the project title',
        'company' => 'Please provide the company name',
        'location' => 'Please provide the project location',
        'email' => 'Please provide your email'
    ];

    foreach ($requiredFields as $field => $message) {
        if (empty($data[$field])) {
            echo json_encode(["message" => $message]);
            http_response_code(400);
            exit;
        }
    }

    // Validate email format
    $emailRegex = '/^[^\s@]+@[^\s@]+\.[^\s@]+$/';
    if (!preg_match($emailRegex, $email)) {
        echo json_encode(["message" => "Please provide a valid email address."]);
        http_response_code(400);
        exit;
    }

    // Insert the new submission
    $stmtInsert = mysqli_prepare($conn, "INSERT INTO 
    clients_survey_form (quality, quality_comments, timeline, timeline_comments, 
    expertise, expertise_comments, communication, communication_comments, resolution, resolution_comments, cleaniness, 
    cleaniness_comments, safety, safety_comments, response, response_comments, electrical_services, mechanical_services, filled_by, position, 
    office_address, phone_number, fax_number, project_title, company, location, email)  
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    
    mysqli_stmt_bind_param($stmtInsert, 'sssssssssssssssssssssssssss', 
        $quality, $quality_comments, $timeline, $timeline_comments, 
        $expertise, $expertise_comments, $communication, $communication_comments, 
        $resolution, $resolution_comments, $cleaniness, $cleaniness_comments, 
        $safety, $safety_comments, $response, $response_comments, 
        $electrical_services, $mechanical_services, $filled_by, $position, 
        $office_address, $phone_number, $fax_number, $project_title, 
        $company, $location, $email
    );

    if (mysqli_stmt_execute($stmtInsert)) {
        // Send both notification emails
        sendNotificationEmails($filled_by, $position, $company, $project_title, $email, $phone_number, $location);
        
        http_response_code(200);
        echo json_encode([
            "message" => "Your entries have been submitted successfully!",
            "data" => $data
        ]);
    } else {
        http_response_code(500);
        echo json_encode(["message" => "Error creating submission."]);
    }
    exit;
} else {
    http_response_code(404);
    echo json_encode(["message" => "Page not found."]);
    exit;
}

function sendNotificationEmails($filled_by, $position, $company, $project_title, $email, $phone_number, $location) {
    $mail = new PHPMailer(true);

    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host = 'mail.lambertelectromec.com.ng';
        $mail->SMTPAuth = true;
        $mail->Username = 'info@lambertelectromec.com.ng';
        $mail->Password = 'Youaregreat@1';
        $mail->SMTPSecure = 'ssl';
        $mail->Port = 465;
        $mail->CharSet = 'UTF-8';

        // Send admin notification
        sendAdminNotification($mail, $filled_by, $position, $company, $project_title, $email, $phone_number, $location);
        
        // Send client confirmation
        sendClientConfirmation($mail, $filled_by, $company, $project_title, $email);

    } catch (Exception $e) {
        error_log("Mail Error: " . $mail->ErrorInfo);
    }
}

function sendAdminNotification($mail, $filled_by, $position, $company, $project_title, $email, $phone_number, $location) {
    // Reset all recipients
    $mail->clearAddresses();
    $mail->clearBCCs();
    
    // Set admin recipients
    $mail->setFrom('info@lambertelectromec.com.ng', 'Client Survey Form Notification');
    $mail->addAddress('m.sofuye@lambertelectromec.com');
    $mail->addBCC('i.nzekwue@lambertelectromec.com');

    // Email content
    $mail->isHTML(true);
    $mail->Subject = "New Client's Survey Submission on $project_title";
    
    // Admin email template
    $mail->Body = "
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='utf-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1'>
        </head>
        <body style='margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f6f9fc;'>
            <div style='max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 0;'>
                <!-- Header -->
                <div style='background: linear-gradient(135deg, #29b476 0%, #1a7b4f 100%); padding: 40px 20px; text-align: center;'>
                    <h1 style='color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;'>New Survey Submission</h1>
                    <p style='color: #ffffff; margin-top: 10px; font-size: 16px;'>Project: $project_title</p>
                </div>

                <!-- Content -->
                <div style='padding: 40px 30px;'>
                    <!-- Client Info Section -->
                    <div style='background-color: #f8fafc; border-radius: 10px; padding: 25px; margin-bottom: 30px;'>
                        <h2 style='margin: 0 0 20px 0; color: #1a7b4f; font-size: 18px; font-weight: 600;'>Client Information</h2>
                        <div style='display: grid; gap: 15px;'>
                            <div style='padding: 15px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);'>
                                <p style='margin: 0; color: #64748b; font-size: 14px;'>Submitted By</p>
                                <p style='margin: 5px 0 0 0; color: #334155; font-size: 16px;'><strong>$filled_by</strong></p>
                                <p style='margin: 5px 0 0 0; color: #64748b; font-size: 14px;'>$position</p>
                            </div>
                            
                            <div style='padding: 15px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);'>
                                <p style='margin: 0; color: #64748b; font-size: 14px;'>Company</p>
                                <p style='margin: 5px 0 0 0; color: #334155; font-size: 16px;'><strong>$company</strong></p>
                            </div>
                        </div>
                    </div>

                    <!-- Contact Details Section -->
                    <div style='background-color: #f8fafc; border-radius: 10px; padding: 25px;'>
                        <h2 style='margin: 0 0 20px 0; color: #1a7b4f; font-size: 18px; font-weight: 600;'>Contact Details</h2>
                        <div style='display: grid; gap: 15px;'>
                            <div style='display: flex; gap: 15px;'>
                                <div style='flex: 1; padding: 15px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);'>
                                    <p style='margin: 0; color: #64748b; font-size: 14px;'>Email</p>
                                    <p style='margin: 5px 0 0 0; color: #334155; font-size: 16px;'>
                                        <a href='mailto:$email' style='color: #29b476; text-decoration: none;'>$email</a>
                                    </p>
                                </div>
                                <div style='flex: 1; padding: 15px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);'>
                                    <p style='margin: 0; color: #64748b; font-size: 14px;'>Phone</p>
                                    <p style='margin: 5px 0 0 0; color: #334155; font-size: 16px;'>$phone_number</p>
                                </div>
                            </div>
                            <div style='padding: 15px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);'>
                                <p style='margin: 0; color: #64748b; font-size: 14px;'>Location</p>
                                <p style='margin: 5px 0 0 0; color: #334155; font-size: 16px;'>$location</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Footer -->
                <div style='background-color: #f8fafc; padding: 20px; text-align: center; border-top: 1px solid #e2e8f0;'>
                    <p style='margin: 0; color: #64748b; font-size: 14px;'>This is an automated notification. Please do not reply.</p>
                </div>
            </div>
        </body>
        </html>
    ";

    $mail->send();
}

function sendClientConfirmation($mail, $filled_by, $company, $project_title, $email) {
    // Reset all recipients
    $mail->clearAddresses();
    $mail->clearBCCs();
    
    // Set client as recipient
    $mail->setFrom('info@lambertelectromec.com.ng', 'Lambert Electromec');
    $mail->addAddress($email, $filled_by);

    // Email content
    $mail->isHTML(true);
    $mail->Subject = "Survey Submission Confirmation - Lambert Electromec";
    
    // Client confirmation email template
    $mail->Body = "
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='utf-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1'>
        </head>
        <body style='margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f6f9fc;'>
            <div style='max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 0;'>
                <!-- Header with Logo -->
                <div style='background: linear-gradient(135deg, #29b476 0%, #1a7b4f 100%); padding: 40px 20px; text-align: center;'>
                    <h1 style='color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;'>Thank You for Your Feedback</h1>
                </div>

                <!-- Content -->
                <div style='padding: 40px 30px;'>
                    <div style='background-color: #f8fafc; border-radius: 10px; padding: 25px; margin-bottom: 30px;'>
                        <h2 style='margin: 0 0 20px 0; color: #1a7b4f; font-size: 18px; font-weight: 600;'>Survey Submission Confirmation</h2>
                        
                        <div style='padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);'>
                            <p style='margin: 0; color: #334155; font-size: 16px; line-height: 1.6;'>
                                Dear <strong>$filled_by</strong>,
                            </p>
                            <p style='margin: 15px 0; color: #334155; font-size: 16px; line-height: 1.6;'>
                                Thank you for taking the time to complete our client survey for the project:
                                <strong>$project_title</strong>
                            </p>
                            <p style='margin: 15px 0; color: #334155; font-size: 16px; line-height: 1.6;'>
                                Your feedback is invaluable to us and will help us improve our services. We appreciate your input and take all feedback seriously.
                            </p>
                            <p style='margin: 15px 0 0 0; color: #334155; font-size: 16px; line-height: 1.6;'>
                                If you have any questions or additional feedback, please don't hesitate to contact us.
                            </p>
                        </div>
                    </div>

                    <!-- Contact Information -->
                    <div style='background-color: #f8fafc; border-radius: 10px; padding: 25px;'>
                        <h2 style='margin: 0 0 20px 0; color: #1a7b4f; font-size: 18px; font-weight: 600;'>Contact Us</h2>
                        <div style='padding: 15px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05);'>
                            <p style='margin: 0; color: #64748b; font-size: 14px;'>Email: m.sofuye@lambertelectromec.com</p>
                            <p style='margin: 5px 0 0 0; color: #64748b; font-size: 14px;'>Website: www.lambertelectromec.com</p>
                        </div>
                    </div>
                </div>

                <!-- Footer -->
                <div style='background-color: #f8fafc; padding: 20px; text-align: center; border-top: 1px solid #e2e8f0;'>
                    <p style='margin: 0; color: #64748b; font-size: 14px;'>© 2024 Lambert Electromec. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
    ";

    $mail->send();
}
