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

$email = $password = "";
$email_err = $password_err = $login_err = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
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
        $password_err = "Please enter your password.";
    } else {
        $password = trim($_POST["password"]);
    }

    // Check for errors before querying the database
    if (empty($email_err) && empty($password_err)) {
        // Prepare a select statement
        $sql = "SELECT id, name, password FROM register WHERE email = ?";

        if ($stmt = $conn->prepare($sql)) {
            // Bind variables to the prepared statement
            $stmt->bind_param("s", $param_email);

            // Set parameters
            $param_email = $email;

            // Execute the statement
            if ($stmt->execute()) {
                // Store result
                $stmt->store_result();

                // Check if email exists
                if ($stmt->num_rows == 1) {
                    // Bind result variables
                    $stmt->bind_result($id, $name, $hashed_password);

                    if ($stmt->fetch()) {
                        // Verify password
                        if (password_verify($password, $hashed_password)) {
                            // Password is correct, start a new session
                            session_start();
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["name"] = $name;

                            // Insert login record into login table
                            $sql_login = "INSERT INTO login (user_id, login_time) VALUES (?, NOW())";
                            if ($stmt_login = $conn->prepare($sql_login)) {
                                $stmt_login->bind_param("i", $id);
                                $stmt_login->execute();
                                $stmt_login->close();
                            }

                            // Redirect user to welcome page
                            header("location: welcome.php");
                        } else {
                            $login_err = "Invalid password.";
                        }
                    }
                } else {
                    $login_err = "No account found with that email.";
                }
            } else {
                echo "Oops! Something went wrong. Please try again later.";
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
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <p>Please fill in your credentials to login.</p>
    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
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
            <input type="submit" value="Login">
        </div>
        <div>
            <span><?php echo $login_err; ?></span>
        </div>
    </form>
</body>
</html>
