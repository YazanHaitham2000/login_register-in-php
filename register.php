<?php
// Database configuration
$servername = "localhost";
$username = "dbyazan";
$password = "0000";
$dbname = "login_register";

// Create connection
$conn = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$name = $email = $password = $confirm_password = "";
$name_err = $email_err = $password_err = $confirm_password_err = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Validate name
    if (empty(trim($_POST["name"]))) {
        $name_err = "Please enter your name.";
    } else {
        $name = trim($_POST["name"]);
    }

    // Validate email
    if (empty(trim($_POST["email"]))) {
        $email_err = "Please enter your email.";
    } elseif (!filter_var(trim($_POST["email"]), FILTER_VALIDATE_EMAIL)) {
        $email_err = "Invalid email format.";
    } else {
        $email = trim($_POST["email"]);
    }

    // Validate password
    if (empty(trim($_POST["password"]))) {
        $password_err = "Please enter a password.";
    } elseif (strlen(trim($_POST["password"])) < 6) {
        $password_err = "Password must be at least 6 characters.";
    } else {
        $password = trim($_POST["password"]);
    }

    // Validate confirm password
    if (empty(trim($_POST["confirm_password"]))) {
        $confirm_password_err = "Please confirm your password.";
    } else {
        $confirm_password = trim($_POST["confirm_password"]);
        if ($password !== $confirm_password) {
            $confirm_password_err = "Passwords do not match.";
        }
    }

    // Check for errors before inserting into database
    if (empty($name_err) && empty($email_err) && empty($password_err) && empty($confirm_password_err)) {
        // Hash the password
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        // Prepare an insert statement
        $sql = "INSERT INTO register (name, email, password) VALUES (?, ?, ?)";

        if ($stmt = $conn->prepare($sql)) {
            // Bind variables to the prepared statement
            $stmt->bind_param("sss", $param_name, $param_email, $param_password);

            // Set parameters
            $param_name = $name;
            $param_email = $email;
            $param_password = $hashed_password;

            // Execute the statement
            if ($stmt->execute()) {
                // Redirect to login page
                header("location: login.php");
                exit;
            } else {
                echo "Something went wrong. Please try again later.";
            }

            // Close statement
            $stmt->close();
        }
    }

    // Close connection
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
</head>
<body>
    <h2>Register</h2>
    <p>Please fill this form to create an account.</p>
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
        <div>
            <label>Name</label>
            <input type="text" name="name" value="<?php echo $name; ?>">
            <span><?php echo $name_err; ?></span>
        </div>    
        <div>
            <label>Email</label>
            <input type="email" name="email" value="<?php echo $email; ?>">
            <span><?php echo $email_err; ?></span>
        </div>
        <div>
            <label>Password</label>
            <input type="password" name="password">
            <span><?php echo $password_err; ?></span>
        </div>
        <div>
            <label>Confirm Password</label>
            <input type="password" name="confirm_password">
            <span><?php echo $confirm_password_err; ?></span>
        </div>
        <div>
            <input type="submit" value="Register">
        </div>
    </form>
</body>
</html>
