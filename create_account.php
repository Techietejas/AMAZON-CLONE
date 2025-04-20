<?php
// Enable error reporting (useful during development; disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Debug information - output to browser during development
echo "<pre>Request received\n";
echo "Request method: " . $_SERVER["REQUEST_METHOD"] . "\n";
echo "POST data: " . print_r($_POST, true) . "</pre>";

// Connect to the database
$servername = "localhost";
$username_db = "root";
$password_db = "";
$dbname = "user_auth";

// Create connection with error handling
try {
    $conn = new mysqli($servername, $username_db, $password_db, $dbname);

    // Check the connection
    if ($conn->connect_error) {
        echo "<p>Connection failed: " . $conn->connect_error . "</p>";
        error_log("Connection failed: " . $conn->connect_error);
        die("Connection failed: " . $conn->connect_error);
    }

    echo "<p>Connected to database successfully</p>";
    error_log("Connected to database successfully");

    // Process the form data when the request method is POST
    if ($_SERVER["REQUEST_METHOD"] === "POST") {
        // Check if required fields are set
        if (isset($_POST['mobilenumber'], $_POST['username'], $_POST['password'])) {
            // Get and sanitize input data
            $mobile = trim($_POST['mobilenumber']);
            $username = trim($_POST['username']);
            $raw_password = $_POST['password'];

            echo "<p>Processing registration for username: " . $username . "</p>";
            error_log("Processing registration for username: " . $username);

            // Validate the mobile number format
            if (!preg_match('/^[0-9]{10}$/', $mobile)) {
                echo "<p>Invalid mobile number format</p>";
                error_log("Invalid mobile number format");
                // Redirect after 3 seconds
                echo "<p>Redirecting to registration page...</p>";
                echo '<meta http-equiv="refresh" content="3;URL=\'createnewaccount.html?error=invalid_mobile\'" />';
                exit();
            }

            // Add a + sign to the mobile number
            $mobile = "+" . $mobile;

            // Hash the password securely
            $hashed_password = password_hash($raw_password, PASSWORD_DEFAULT);

            // Prepare an SQL statement to prevent SQL injection
            $stmt = $conn->prepare("INSERT INTO users (mobile_number, username, password) VALUES (?, ?, ?)");
            if (!$stmt) {
                echo "<p>Prepare failed: " . $conn->error . "</p>";
                error_log("Prepare failed: " . $conn->error);
                // Redirect after 3 seconds
                echo "<p>Redirecting to registration page...</p>";
                echo '<meta http-equiv="refresh" content="3;URL=\'createnewaccount.html?error=db_prepare\'" />';
                exit();
            }

            // Bind the parameters to the SQL query
            $stmt->bind_param("sss", $mobile, $username, $hashed_password);

            // Execute the statement and check for success
            if ($stmt->execute()) {
                echo "<p>Account created successfully for: " . $username . "</p>";
                error_log("Account created successfully for: " . $username);
                // Redirect after 3 seconds
                echo "<p>Redirecting to login page...</p>";
                echo '<meta http-equiv="refresh" content="3;URL=\'login.html?success=account_created\'" />';
                exit();
            } else {
                echo "<p>Execute failed: " . $stmt->error . "</p>";
                error_log("Execute failed: " . $stmt->error);
                // Check if error is due to duplicate entry
                if ($conn->errno === 1062) {
                    // Redirect after 3 seconds
                    echo "<p>User already exists. Redirecting...</p>";
                    echo '<meta http-equiv="refresh" content="3;URL=\'createnewaccount.html?error=duplicate_user\'" />';
                } else {
                    // Redirect after 3 seconds
                    echo "<p>Database error. Redirecting...</p>";
                    echo '<meta http-equiv="refresh" content="3;URL=\'createnewaccount.html?error=db_error\'" />';
                }
                exit();
            }

            // Close the prepared statement
            $stmt->close();
        } else {
            echo "<p>Missing required fields</p>";
            error_log("Missing required fields");
            // Redirect after 3 seconds
            echo "<p>Redirecting to registration page...</p>";
            echo '<meta http-equiv="refresh" content="3;URL=\'createnewaccount.html?error=missing_fields\'" />';
            exit();
        }
    } else {
        echo "<p>Invalid request method</p>";
        error_log("Invalid request method");
        // Redirect after 3 seconds
        echo "<p>Redirecting to registration page...</p>";
        echo '<meta http-equiv="refresh" content="3;URL=\'createnewaccount.html?error=invalid_method\'" />';
        exit();
    }

    // Close the database connection
    $conn->close();
    
} catch (Exception $e) {
    echo "<p>An error occurred: " . $e->getMessage() . "</p>";
    error_log("Exception: " . $e->getMessage());
    // Redirect after 5 seconds
    echo "<p>Redirecting to registration page...</p>";
    echo '<meta http-equiv="refresh" content="5;URL=\'createnewaccount.html?error=server_error\'" />';
    exit();
}
?>
