<?php
/**
 * Returns the HTML email body for an application form submission.
 * 
 * @param array $data Associative array of all form fields and image URLs.
 * @param string $recipient 'admin' or 'user'
 * @return string HTML email body
 */

function getAdminApplicationEmail($data){
extract($data);

return "
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>New Application Submission</title>
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
    .message {
        background-color: #f0f0f0;
        padding: 15px;
        border-radius: 6px;
        font-style: italic;
        color: #444444;
        margin-bottom: 20px;
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
    <img src='https://api.chefmasterafrica.org/servers/chefmaster_db/uploads/chefmaster.png' alt='Envelope Icon'>
    </div>

    <h2 class='header'>Hi " . htmlspecialchars($fullName) . ",</h2>
    <p>New Application Submission</p>

    <hr style='border: none; border-top: 1px solid #eee; margin: 30px 0;'>

    <p><strong>FullName:</strong></p>
    <div class='message'>" . htmlspecialchars($fullName ?? '') . "</div>

    <p><strong>Date of Birth:</strong></p>
    <div class='message'>" . htmlspecialchars($dob ?? '') . "</div>

    <p><strong>Gender:</strong></p>
    <div class='message'>" . htmlspecialchars($gender ?? '') . "</div>

    <p><strong>State:</strong></p>
    <div class='message'>" . htmlspecialchars($state_of_origin ?? '') . "</div>

    <p><strong>Email:</strong></p>
    <div class='message'>" . htmlspecialchars($email ?? '') . "</div>

    <p><strong>Phone:</strong></p>
    <div class='message'>" . htmlspecialchars($phone ?? '') . "</div>

    <p><strong>Address:</strong></p>
    <div class='message'>" . htmlspecialchars($address ?? '') . "</div>

    <p><strong>City:</strong></p>
    <div class='message'>" . htmlspecialchars($city ?? '') . "</div>

    <p><strong>State:</strong></p>
    <div class='message'>" . htmlspecialchars($state ?? '') . "</div>

    <p><strong>Zip Code:</strong></p>
    <div class='message'>" . htmlspecialchars($zip_code ?? '') . "</div>
    
    <p><strong>Current Occupation:</strong></p>
    <div class='message'>" . htmlspecialchars($occupation ?? '') . "</div>

    <p><strong>Years of Experience in cooking:</strong></p>
    <div class='message'>" . htmlspecialchars($years_of_experience ?? '') . "</div>

    <p><strong>Culinary Training/Education:</strong></p>
    <div class='message'>" . htmlspecialchars($culinary_training ?? '') . "</div>

    <p><strong>Degree/Certificate:</strong></p>
    <div class='message'>" . htmlspecialchars($degree ?? '') . "</div>

    <p><strong>Graduation Year:</strong></p>
    <div class='message'>" . htmlspecialchars($graduation_year ?? '') . "</div>

    <p><strong>Specialized Category:</strong></p>
    <div class='message'>" . htmlspecialchars($specialized_category ?? '') . "</div>

    <p><strong>Food Allergies:</strong></p>
    <div class='message'>" . htmlspecialchars($food_allergies ?? '') . "</div>

    <p><strong>What's Signature Dish:</strong></p>
    <div class='message'>" . htmlspecialchars($signature_dish ?? '') . "</div>

    <p><strong>Describe your Signature Dish:</strong></p>
    <div class='message'>" . htmlspecialchars($signature_dish_description ?? '') . "</div>

    <p><strong>Why do you want to participate in this competition?:</strong></p>
    <div class='message'>" . htmlspecialchars($participation_reason ?? '') . "</div>

    <p><strong>Emergency Contact Name:</strong></p>
    <div class='message'>" . htmlspecialchars($fullName_emergency_contact ?? '') . "</div>

    <p><strong>Relationship:</strong></p>
    <div class='message'>" . htmlspecialchars($relationship ?? '') . "</div>

    <p><strong>Emergency Contact Phone:</strong></p>
    <div class='message'>" . htmlspecialchars($phone_emergency ?? '') . "</div>

    <p><strong>Emergency Contact Address:</strong></p>
    <div class='message'>" . htmlspecialchars($address_emergency ?? '') . "</div>

    <p><strong>Emergency Contact City:</strong></p>
    <div class='message'>" . htmlspecialchars($city_emergency ?? '') . "</div>

    <p><strong>Emergency Contact State:</strong></p>
    <div class='message'>" . htmlspecialchars($state_emergency ?? '') . "</div>

    <p><strong>Emergency Contact Zip Code:</strong></p>
    <div class='message'>" . htmlspecialchars($zip_code_emergency ?? '') . "</div>

    <p><strong>How did you hear about this competition?:</strong></p>
    <div class='message'>" . htmlspecialchars($competition_knowledge ?? '') . "</div>

    <p><strong>Passport Image Link:</strong></p>
    <div class='message'>" . (!empty($passport_image_url) ? "<a href='" . htmlspecialchars($passport_image_url) . "' target='_blank'>View Image</a>" : "Not Provided") . "</div>

    <p><strong>Signature Image Link:</strong></p>
    <div class='message'>" . (!empty($signature_image_url) ? "<a href='" . htmlspecialchars($signature_image_url) . "' target='_blank'>View Image</a>" : "Not Provided") . "</div>


    <a href='https://chefmasterafrica.org' class='btn'>VISIT WEBSITE</a>

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

}



function getUserApplicationEmail($data){
extract($data);

return "
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<title>New Application Submission</title>
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
    .message {
        background-color: #f0f0f0;
        padding: 15px;
        border-radius: 6px;
        font-style: italic;
        color: #444444;
        margin-bottom: 20px;
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
    <img src='https://api.chefmasterafrica.org/servers/chefmaster_db/uploads/chefmaster.png' alt='Envelope Icon'>
    </div>

    <h2 class='header'>Hi " . htmlspecialchars($fullName) . ",</h2>
    <p>Thank you for submitting your application to Chef Master Africa. We have received your details as follows</p>

    <hr style='border: none; border-top: 1px solid #eee; margin: 30px 0;'>

    <p><strong>Date of Birth:</strong></p>
    <div class='message'>" . htmlspecialchars($dob ?? '') . "</div>

    <p><strong>Gender:</strong></p>
    <div class='message'>" . htmlspecialchars($gender ?? '') . "</div>

    <p><strong>Email:</strong></p>
    <div class='message'>" . htmlspecialchars($email ?? '') . "</div>

    <p><strong>Phone:</strong></p>
    <div class='message'>" . htmlspecialchars($phone ?? '') . "</div>

    <p><strong>Address:</strong></p>
    <div class='message'>" . htmlspecialchars($address ?? '') . "</div>

    <p><strong>Occupation:</strong></p>
    <div class='message'>" . htmlspecialchars($occupation ?? '') . "</div>

    <p><strong>Years of Experience:</strong></p>
    <div class='message'>" . htmlspecialchars($years_of_experience ?? '') . "</div>

    <p><strong>Culinary Training:</strong></p>
    <div class='message'>" . htmlspecialchars($culinary_training ?? '') . "</div>

    <p><strong>Degree:</strong></p>
    <div class='message'>" . htmlspecialchars($degree ?? '') . "</div>

    <p><strong>Graduation Year:</strong></p>
    <div class='message'>" . htmlspecialchars($graduation_year ?? '') . "</div>

    <p><strong>Specialized Category:</strong></p>
    <div class='message'>" . htmlspecialchars($specialized_category ?? '') . "</div>

    <p><strong>Food Allergies:</strong></p>
    <div class='message'>" . htmlspecialchars($food_allergies ?? '') . "</div>

    <p><strong>Signature Dish:</strong></p>
    <div class='message'>" . htmlspecialchars($signature_dish ?? '') . "</div>

    <p><strong>Signature Dish Description:</strong></p>
    <div class='message'>" . htmlspecialchars($signature_dish_description ?? '') . "</div>

    <p><strong>Participation Reason:</strong></p>
    <div class='message'>" . htmlspecialchars($participation_reason ?? '') . "</div>

    <p><strong>Emergency Contact Name:</strong></p>
    <div class='message'>" . htmlspecialchars($fullName_emergency_contact ?? '') . "</div>

    <p><strong>Relationship:</strong></p>
    <div class='message'>" . htmlspecialchars($relationship ?? '') . "</div>

    <p><strong>Emergency Contact Phone:</strong></p>
    <div class='message'>" . htmlspecialchars($phone_emergency ?? '') . "</div>

    <p><strong>Emergency Contact Address:</strong></p>
    <div class='message'>" . htmlspecialchars($address_emergency ?? '') . "</div>


    <a href='https://chefmasterafrica.org' class='btn'>VISIT WEBSITE</a>

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

}
?>