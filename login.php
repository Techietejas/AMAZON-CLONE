<?php
// Enable error reporting (useful during development; disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Start the session
session_start();

// Database connection parameters
$servername = "localhost";
$username_db = "root";
$password_db = "";
$dbname = "user_auth";

// Create a connection to the database
$conn = new mysqli($servername, $username_db, $password_db, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Process form data when the request method is POST
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Check if the required fields are set
    if (isset($_POST['username'], $_POST['password'])) {
        // Get and sanitize user input
        $username = trim($_POST['username']);
        $raw_password = $_POST['password'];

        // Prepare an SQL statement to prevent SQL injection
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        if (!$stmt) {
            die("Prepare failed: " . $conn->error);
        }
        
        // Bind the parameters to the SQL query
        $stmt->bind_param("s", $username);
        $stmt->execute();

        // Get the result
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            // Fetch user data
            $user = $result->fetch_assoc();

            // Verify the password against the stored hash
            if (password_verify($raw_password, $user['password'])) {
                // Set session variable
                $_SESSION['user'] = $user['username'];
                // Redirect to index page
                header("Location: index.html");
                exit();
            } else {
                header("Location: login.html?error=invalid_password");
                exit();
            }
        } else {
            header("Location: login.html?error=user_not_found");
            exit();
        }
        
        // Close the statement
        $stmt->close();
    } else {
        header("Location: login.html?error=missing_fields");
        exit();
    }
} else {
    header("Location: login.html?error=invalid_method");
    exit();
}

// Close the database connection
$conn->close();
?>
