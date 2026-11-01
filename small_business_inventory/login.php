<?php
session_start();

require_once __DIR__ . "/config/database.php";

$message = "";
$messageType = "danger";
$email = "";

// Generate CSRF token
if (
    !isset($_SESSION["csrf_token"]) ||
    !is_string($_SESSION["csrf_token"]) ||
    $_SESSION["csrf_token"] === ""
) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

/**
 * @param mixed $value
 * @return string
 */
function escape($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES, "UTF-8");
}

// Registration success message
if (isset($_GET["registered"])) {
    $message = "Registration successful! You can now log in.";
    $messageType = "success";
}

// Process login
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // Validate CSRF token
    $submittedToken = $_POST["csrf_token"] ?? "";

    if (
        !is_string($submittedToken) ||
        !isset($_SESSION["csrf_token"]) ||
        !is_string($_SESSION["csrf_token"]) ||
        !hash_equals($_SESSION["csrf_token"], $submittedToken)
    ) {
        http_response_code(403);
        exit("Invalid or expired form token. Please refresh the page and try again.");
    }

    // Get input values safely
    $emailInput = $_POST["email"] ?? "";
    $passwordInput = $_POST["password"] ?? "";

    $email = is_string($emailInput)
        ? strtolower(trim($emailInput))
        : "";

    $password = is_string($passwordInput)
        ? $passwordInput
        : "";

    if ($email === "" || $password === "") {

        $message = "Please enter your email and password.";

    } elseif (
        strlen($email) > 254 ||
        !filter_var($email, FILTER_VALIDATE_EMAIL)
    ) {

        $message = "Incorrect email or password.";

    } elseif (strlen($password) > 4096) {

        $message = "Incorrect email or password.";

    } else {

        // Find user account
        $stmt = $conn->prepare(
            "SELECT id, name, email, password, role
             FROM users
             WHERE email = ?
             LIMIT 1"
        );

        if (!$stmt) {
            error_log("Login prepare failed: " . $conn->error);

            http_response_code(500);
            exit("Something went wrong. Please try again later.");
        }

        $stmt->bind_param("s", $email);

        if (!$stmt->execute()) {
            error_log("Login execution failed: " . $stmt->error);

            $stmt->close();

            http_response_code(500);
            exit("Unable to process login. Please try again later.");
        }

        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        $stmt->close();

        // Verify password
        if (
            $user &&
            password_verify($password, (string)$user["password"])
        ) {

            // Verify allowed account role
            $userRole = strtolower(trim((string)$user["role"]));

            if (!in_array($userRole, ["administrator", "owner"], true)) {
                $message = "Incorrect email or password.";

            } else {

                // Prevent session fixation
                session_regenerate_id(true);

                // Store authenticated user information
                $_SESSION["user_id"] = (int)$user["id"];
                $_SESSION["user_name"] = $user["name"];
                $_SESSION["user_role"] = $userRole;

                // Generate a new CSRF token after login
                $_SESSION["csrf_token"] = bin2hex(random_bytes(32));

                header("Location: dashboard.php");
                exit;
            }

        } else {

            // Use the same message for unknown email and wrong password
            $message = "Incorrect email or password.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Login | Small Business Inventory</title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"
        rel="stylesheet"
    >

    <link rel="stylesheet" href="css/style.css">

    <style>
        .password-wrapper {
            position: relative;
        }

        .password-wrapper input {
            padding-right: 50px;
        }

        .toggle-password {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            border: none;
            background: transparent;
            color: #888;
            font-size: 22px;
            cursor: pointer;
            padding: 3px;
            line-height: 1;
        }

        .toggle-password:hover {
            color: #172033;
        }
    </style>
</head>

<body class="bg-light">

<div class="container py-5">

    <div class="row justify-content-center">

        <div class="col-md-6 col-lg-5">

            <div class="card shadow border-0">

                <div class="card-body p-4">

                    <h2 class="text-center mb-2">
                        Welcome Back
                    </h2>

                    <p class="text-center text-muted mb-4">
                        Small Business Inventory and Sales Management
                    </p>

                    <?php if ($message !== ""): ?>

                        <div class="alert alert-<?= escape($messageType) ?>">
                            <?= escape($message) ?>
                        </div>

                    <?php endif; ?>

                    <form method="POST" action="login.php">

                        <!-- CSRF Token -->
                        <input
                            type="hidden"
                            name="csrf_token"
                            value="<?= escape($_SESSION["csrf_token"]) ?>"
                        >

                        <div class="mb-3">

                            <label class="form-label">
                                Email Address
                            </label>

                            <input
                                type="email"
                                name="email"
                                class="form-control"
                                maxlength="254"
                               value="<?= escape($email) ?>"
                                required
                            >

                        </div>

                        <div class="mb-3">

                            <label class="form-label">
                                Password
                            </label>

                            <div class="password-wrapper">

                                <input
                                    type="password"
                                    name="password"
                                    id="password"
                                    class="form-control"
                                    maxlength="4096"
                                    required
                                >

                                <button
                                    type="button"
                                    class="toggle-password"
                                    onclick="togglePassword('password', this)"
                                    aria-label="Show password"
                                >
                                    <i class="bi bi-eye-slash"></i>
                                </button>

                            </div>

                        </div>

                        <button
                            type="submit"
                            class="btn btn-success w-100"
                        >
                            Login
                        </button>

                    </form>

                    <p class="text-center mt-3 mb-0">

                        Don't have an account?

                        <a href="register.php">
                            Register here
                        </a>

                    </p>

                </div>

            </div>

        </div>

    </div>

</div>

<script>
function togglePassword(inputId, button) {

    const input = document.getElementById(inputId);
    const icon = button.querySelector("i");

    if (input.type === "password") {

        input.type = "text";

        icon.classList.remove("bi-eye-slash");
        icon.classList.add("bi-eye");

        button.setAttribute("aria-label", "Hide password");

    } else {

        input.type = "password";

        icon.classList.remove("bi-eye");
        icon.classList.add("bi-eye-slash");

        button.setAttribute("aria-label", "Show password");
    }
}
</script>

</body>
</html>