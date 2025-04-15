<?php
// Enable error reporting (useful during development; disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Debug information
error_log("Request received");
error_log("Request method: " . $_SERVER["REQUEST_METHOD"]);
error_log("POST data: " . print_r($_POST, true));

// Connect to the database
$servername = "localhost";
$username_db = "root";
$password_db = "";
$dbname = "user_auth";

$conn = new mysqli($servername, $username_db, $password_db, $dbname);

// Check the connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Process the form data when the request method is POST
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Check if required fields are set
    if (isset($_POST['mobilenumber'], $_POST['username'], $_POST['password'])) {
        // Get and sanitize input data
        $mobile = trim($_POST['mobilenumber']);
        $username = trim($_POST['username']);
        $raw_password = $_POST['password'];

        // Validate the mobile number format (should be 10 digits)
        if (!preg_match('/^[0-9]{10}$/', $mobile)) {
            die("Error: Invalid mobile number. It should be exactly 10 digits.");
        }

        // Hash the password securely
        $hashed_password = password_hash($raw_password, PASSWORD_DEFAULT);

        // Prepare an SQL statement to prevent SQL injection
        $stmt = $conn->prepare("INSERT INTO users (mobile_number, username, password) VALUES (?, ?, ?)");
        if (!$stmt) {
            die("Prepare failed: " . $conn->error);
        }

        // Bind the parameters to the SQL query
        $stmt->bind_param("sss", $mobile, $username, $hashed_password);

        // Execute the statement and check for success
        if ($stmt->execute()) {
            header("Location: login.html?success=account_created");
            exit();
        } else {
            header("Location: createnewaccount.html?error=db_error");
            exit();
        }

        // Close the prepared statement
        $stmt->close();
    } else {
        header("Location: createnewaccount.html?error=missing_fields");
        exit();
    }
} else {
    header("Location: createnewaccount.html?error=invalid_method");
    exit();
}

// Close the database connection
$conn->close();
?>
