<?php
session_start();

require_once __DIR__ . "/config/database.php";

// Generate CSRF token
if (
    !isset($_SESSION["csrf_token"]) ||
    !is_string($_SESSION["csrf_token"]) ||
    $_SESSION["csrf_token"] === ""
) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

$message = "";
$name = "";
$email = "";

// Process registration
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

    // Get form values safely
    $nameInput = $_POST["name"] ?? "";
    $emailInput = $_POST["email"] ?? "";
    $passwordInput = $_POST["password"] ?? "";
    $confirmInput = $_POST["confirm_password"] ?? "";

    $name = is_string($nameInput)
        ? trim($nameInput)
        : "";

    $email = is_string($emailInput)
        ? strtolower(trim($emailInput))
        : "";

    $password = is_string($passwordInput)
        ? $passwordInput
        : "";

    $confirm_password = is_string($confirmInput)
        ? $confirmInput
        : "";

    // Validate inputs
    if (
        $name === "" ||
        $email === "" ||
        $password === "" ||
        $confirm_password === ""
    ) {
        $message = "Please complete all required fields.";

    } elseif (strlen($name) > 150) {
        $message = "Name must not exceed 150 characters.";

    } elseif (strlen($email) > 254) {
        $message = "Email address is too long.";

    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $message = "Please enter a valid email address.";

    } elseif (strlen($password) < 8) {
        $message = "Password must be at least 8 characters.";

    } elseif (strlen($password) > 4096) {
        $message = "Password is too long.";

    } elseif ($password !== $confirm_password) {
        $message = "Passwords do not match.";

    } else {

        // Check if email already exists
        $check = $conn->prepare(
            "SELECT id FROM users WHERE email = ? LIMIT 1"
        );

        if (!$check) {
            error_log("Registration email check failed: " . $conn->error);
            http_response_code(500);
            exit("Something went wrong. Please try again later.");
        }

        $check->bind_param("s", $email);

        if (!$check->execute()) {
            error_log("Registration email check execution failed: " . $check->error);
            $check->close();

            http_response_code(500);
            exit("Unable to process registration.");
        }

        $result = $check->get_result();

        if ($result->num_rows > 0) {

            $message = "Email is already registered.";

        } else {

            // Hash password
            $hashed_password = password_hash(
                $password,
                PASSWORD_DEFAULT
            );

            if ($hashed_password === false) {
                $check->close();

                http_response_code(500);
                exit("Unable to secure your password.");
            }

            // Public registration can only create Owner accounts
            $role = "owner";

            $stmt = $conn->prepare(
                "INSERT INTO users (name, email, password, role)
                 VALUES (?, ?, ?, ?)"
            );

            if (!$stmt) {
                error_log("Registration insert prepare failed: " . $conn->error);
                $check->close();

                http_response_code(500);
                exit("Unable to create your account.");
            }

            $stmt->bind_param(
                "ssss",
                $name,
                $email,
                $hashed_password,
                $role
            );

            if ($stmt->execute()) {

                $stmt->close();
                $check->close();

                // Regenerate CSRF token
                $_SESSION["csrf_token"] = bin2hex(random_bytes(32));

                header("Location: login.php?registered=1");
                exit;

            } else {

                // Handle duplicate email or database error
                if ($stmt->errno === 1062) {
                    $message = "Email is already registered.";
                } else {
                    error_log("Registration insert failed: " . $stmt->error);
                    $message = "Registration failed. Please try again.";
                }
            }

            $stmt->close();
        }

        $check->close();
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Register | Small Business Inventory</title>

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
                        Create Account
                    </h2>

                    <p class="text-center text-muted mb-4">
                        Small Business Inventory and Sales Management
                    </p>

                    <?php if ($message !== ""): ?>

                        <div class="alert alert-danger">
                            <?= htmlspecialchars($message, ENT_QUOTES, "UTF-8") ?>
                        </div>

                    <?php endif; ?>

                    <form method="POST" action="register.php">

                        <input
                            type="hidden"
                            name="csrf_token"
                            value="<?= htmlspecialchars($_SESSION["csrf_token"], ENT_QUOTES, "UTF-8") ?>"
                        >

                        <div class="mb-3">

                            <label class="form-label">
                                Full Name
                            </label>

                            <input
                                type="text"
                                name="name"
                                class="form-control"
                                maxlength="150"
                                value="<?= htmlspecialchars($name, ENT_QUOTES, "UTF-8") ?>"
                                required
                            >

                        </div>

                        <div class="mb-3">

                            <label class="form-label">
                                Email Address
                            </label>

                            <input
                                type="email"
                                name="email"
                                class="form-control"
                                maxlength="254"
                                value="<?= htmlspecialchars($email, ENT_QUOTES, "UTF-8") ?>"
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
                                    minlength="8"
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

                        <div class="mb-3">

                            <label class="form-label">
                                Confirm Password
                            </label>

                            <div class="password-wrapper">

                                <input
                                    type="password"
                                    name="confirm_password"
                                    id="confirm_password"
                                    class="form-control"
                                    minlength="8"
                                    maxlength="4096"
                                    required
                                >

                                <button
                                    type="button"
                                    class="toggle-password"
                                    onclick="togglePassword('confirm_password', this)"
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
                            Register
                        </button>

                    </form>

                    <p class="text-center mt-3 mb-0">
                        Already have an account?

                        <a href="login.php">
                            Login here
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