<?php
// Enable error reporting (useful during development; disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Start the session
session_start();

// Debug information - output to browser during development
echo "<pre>Login request received\n";
echo "Request method: " . $_SERVER["REQUEST_METHOD"] . "\n";
echo "POST data: " . print_r($_POST, true) . "</pre>";

// Database connection parameters
$servername = "localhost";
$username_db = "root";
$password_db = "";
$dbname = "user_auth";

try {
    // Create a connection to the database
    $conn = new mysqli($servername, $username_db, $password_db, $dbname);

    // Check connection
    if ($conn->connect_error) {
        echo "<p>Connection failed: " . $conn->connect_error . "</p>";
        error_log("Connection failed: " . $conn->connect_error);
        die("Connection failed: " . $conn->connect_error);
    }

    echo "<p>Connected to database successfully</p>";
    error_log("Connected to database successfully");

    // Process form data when the request method is POST
    if ($_SERVER["REQUEST_METHOD"] === "POST") {
        // Check if the required fields are set
        if (isset($_POST['username'], $_POST['password'])) {
            // Get and sanitize user input
            $username = trim($_POST['username']);
            $raw_password = $_POST['password'];

            echo "<p>Processing login for username: " . $username . "</p>";
            error_log("Processing login for username: " . $username);

            // Try to find user by username first
            $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
            if (!$stmt) {
                echo "<p>Prepare failed: " . $conn->error . "</p>";
                error_log("Prepare failed: " . $conn->error);
                // Redirect after 3 seconds
                echo "<p>Redirecting to login page...</p>";
                echo '<meta http-equiv="refresh" content="3;URL=\'login.html?error=db_error\'" />';
                exit();
            }
            
            // Bind the parameters to the SQL query
            $stmt->bind_param("s", $username);
            $stmt->execute();

            // Get the result
            $result = $stmt->get_result();
            
            // If user not found by username, try by mobile number
            if ($result->num_rows == 0) {
                $stmt->close();
                
                // Add + sign to the username if it's numeric (mobile number)
                if (is_numeric($username) && strlen($username) == 10) {
                    $mobile = "+" . $username;
                    echo "<p>Username not found, trying mobile number: " . $mobile . "</p>";
                    
                    $stmt = $conn->prepare("SELECT * FROM users WHERE mobile_number = ?");
                    if (!$stmt) {
                        echo "<p>Prepare failed: " . $conn->error . "</p>";
                        error_log("Prepare failed: " . $conn->error);
                        // Redirect after 3 seconds
                        echo "<p>Redirecting to login page...</p>";
                        echo '<meta http-equiv="refresh" content="3;URL=\'login.html?error=db_error\'" />';
                        exit();
                    }
                    
                    $stmt->bind_param("s", $mobile);
                    $stmt->execute();
                    $result = $stmt->get_result();
                }
            }
            
            if ($result->num_rows > 0) {
                // Fetch user data
                $user = $result->fetch_assoc();
                echo "<p>User found, verifying password</p>";

                // Verify the password against the stored hash
                if (password_verify($raw_password, $user['password'])) {
                    // Set session variable
                    $_SESSION['user'] = $user['username'];
                    $_SESSION['user_id'] = $user['id'];
                    echo "<p>Login successful for: " . $username . "</p>";
                    error_log("Login successful for: " . $username);
                    
                    // Redirect after 3 seconds
                    echo "<p>Redirecting to index page...</p>";
                    echo '<meta http-equiv="refresh" content="3;URL=\'index.html\'" />';
                    exit();
                } else {
                    echo "<p>Invalid password for: " . $username . "</p>";
                    error_log("Invalid password for: " . $username);
                    // Redirect after 3 seconds
                    echo "<p>Redirecting to login page...</p>";
                    echo '<meta http-equiv="refresh" content="3;URL=\'login.html?error=invalid_password\'" />';
                    exit();
                }
            } else {
                echo "<p>User not found: " . $username . "</p>";
                error_log("User not found: " . $username);
                // Redirect after 3 seconds
                echo "<p>Redirecting to login page...</p>";
                echo '<meta http-equiv="refresh" content="3;URL=\'login.html?error=user_not_found\'" />';
                exit();
            }
            
            // Close the statement
            $stmt->close();
        } else {
            echo "<p>Missing fields in login form</p>";
            error_log("Missing fields in login form");
            // Redirect after 3 seconds
            echo "<p>Redirecting to login page...</p>";
            echo '<meta http-equiv="refresh" content="3;URL=\'login.html?error=missing_fields\'" />';
            exit();
        }
    } else {
        echo "<p>Invalid request method for login</p>";
        error_log("Invalid request method for login");
        // Redirect after 3 seconds
        echo "<p>Redirecting to login page...</p>";
        echo '<meta http-equiv="refresh" content="3;URL=\'login.html?error=invalid_method\'" />';
        exit();
    }

    // Close the database connection
    $conn->close();
    
} catch (Exception $e) {
    echo "<p>An error occurred: " . $e->getMessage() . "</p>";
    error_log("Exception: " . $e->getMessage());
    // Redirect after 5 seconds
    echo "<p>Redirecting to login page...</p>";
    echo '<meta http-equiv="refresh" content="5;URL=\'login.html?error=server_error\'" />';
    exit();
}
?>
