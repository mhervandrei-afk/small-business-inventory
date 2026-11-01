<?php
session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

require_once __DIR__ . "/config/database.php";

$userId = (int) $_SESSION["user_id"];
$message = "";
$messageType = "";

// Generate CSRF token
if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // Validate CSRF token
    $submittedToken = $_POST["csrf_token"] ?? "";

    if (
        !is_string($submittedToken) ||
        !isset($_SESSION["csrf_token"]) ||
        !hash_equals($_SESSION["csrf_token"], $submittedToken)
    ) {
        $message = "Invalid request. Please refresh the page and try again.";
        $messageType = "danger";

    } else {

        $currentPassword = $_POST["current_password"] ?? "";
        $newPassword = $_POST["new_password"] ?? "";
        $confirmPassword = $_POST["confirm_password"] ?? "";

        if (
            !is_string($currentPassword) ||
            !is_string($newPassword) ||
            !is_string($confirmPassword)
        ) {
            $message = "Invalid password input.";
            $messageType = "danger";

        } elseif (
            $currentPassword === "" ||
            $newPassword === "" ||
            $confirmPassword === ""
        ) {
            $message = "Please fill in all fields.";
            $messageType = "danger";

        } elseif (strlen($newPassword) < 8) {
            $message = "New password must be at least 8 characters.";
            $messageType = "danger";

        } elseif ($newPassword !== $confirmPassword) {
            $message = "New password and confirmation do not match.";
            $messageType = "danger";

        } elseif ($newPassword === $currentPassword) {
            $message = "Your new password must be different from your current password.";
            $messageType = "danger";

        } else {

            // Get current password from database
            $stmt = $conn->prepare(
                "SELECT password FROM users WHERE id = ?"
            );

            if (!$stmt) {
                $message = "Unable to process your request. Please try again.";
                $messageType = "danger";

            } else {

                $stmt->bind_param("i", $userId);
                $stmt->execute();

                $result = $stmt->get_result();
                $user = $result->fetch_assoc();

                $stmt->close();

                if (
                    !$user ||
                    !password_verify($currentPassword, $user["password"])
                ) {
                    $message = "Your current password is incorrect.";
                    $messageType = "danger";

                } else {

                    // Hash new password
                    $hashedPassword = password_hash(
                        $newPassword,
                        PASSWORD_DEFAULT
                    );

                    // Update password
                    $update = $conn->prepare(
                        "UPDATE users SET password = ? WHERE id = ?"
                    );

                    if (!$update) {
                        $message = "Unable to change password. Please try again.";
                        $messageType = "danger";

                    } else {

                        $update->bind_param(
                            "si",
                            $hashedPassword,
                            $userId
                        );

                        if ($update->execute()) {

                            $message = "Password changed successfully!";
                            $messageType = "success";

                            // Regenerate session ID and CSRF token
                            session_regenerate_id(true);

                            $_SESSION["csrf_token"] = bin2hex(
                                random_bytes(32)
                            );

                        } else {
                            $message = "Unable to change password. Please try again.";
                            $messageType = "danger";
                        }

                        $update->close();
                    }
                }
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Change Password | Small Business Inventory</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

    <style>
        body {
            background: #f4f6f9;
            font-family: Arial, sans-serif;
        }

        .navbar {
            background: #172033;
            padding: 15px 25px;
        }

        .navbar-brand {
            color: white;
            font-weight: bold;
        }

        .main-container {
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
        }

        .password-card {
            background: white;
            padding: 35px;
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
        }

        h3 {
            color: #172033;
            font-weight: bold;
            margin-bottom: 10px;
        }

        .form-label {
            font-weight: 600;
            color: #172033;
        }

        .password-wrapper {
            position: relative;
        }

        .password-wrapper input {
            padding-right: 50px;
            height: 48px;
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

        .btn-orange {
            background: #ff9418;
            color: white;
            border: none;
            padding: 11px;
            font-weight: bold;
        }

        .btn-orange:hover {
            background: #e6810b;
            color: white;
        }

        .btn-back {
            background: #172033;
            color: white;
            padding: 11px;
        }

        .btn-back:hover {
            background: #263653;
            color: white;
        }
    </style>
</head>

<body>

<nav class="navbar">
    <a class="navbar-brand text-decoration-none" href="dashboard.php">
        Small Business Inventory
    </a>
</nav>

<div class="main-container">

    <div class="password-card">

        <h3>Change Password</h3>

        <p class="text-muted mb-4">
            Update your account password to keep it secure.
        </p>

        <?php if ($message !== ""): ?>
            <div class="alert alert-<?= htmlspecialchars($messageType, ENT_QUOTES, "UTF-8") ?>">
                <?= htmlspecialchars($message, ENT_QUOTES, "UTF-8") ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="change_password.php">

            <!-- CSRF Token -->
            <input
                type="hidden"
                name="csrf_token"
                value="<?= htmlspecialchars($_SESSION["csrf_token"], ENT_QUOTES, "UTF-8") ?>"
            >

            <!-- Current Password -->
            <div class="mb-3">
                <label class="form-label">Current Password</label>

                <div class="password-wrapper">
                    <input
                        type="password"
                        name="current_password"
                        id="current_password"
                        class="form-control"
                        placeholder="Enter current password"
                        autocomplete="current-password"
                        required
                    >

                    <button
                        type="button"
                        class="toggle-password"
                        onclick="togglePassword('current_password', this)"
                        aria-label="Show password"
                    >
                        <i class="bi bi-eye-slash"></i>
                    </button>
                </div>
            </div>

            <!-- New Password -->
            <div class="mb-3">
                <label class="form-label">New Password</label>

                <div class="password-wrapper">
                    <input
                        type="password"
                        name="new_password"
                        id="new_password"
                        class="form-control"
                        placeholder="Enter new password"
                        minlength="8"
                        autocomplete="new-password"
                        required
                    >

                    <button
                        type="button"
                        class="toggle-password"
                        onclick="togglePassword('new_password', this)"
                        aria-label="Show password"
                    >
                        <i class="bi bi-eye-slash"></i>
                    </button>
                </div>

                <small class="text-muted">
                    Password must be at least 8 characters.
                </small>
            </div>

            <!-- Confirm Password -->
            <div class="mb-4">
                <label class="form-label">Confirm New Password</label>

                <div class="password-wrapper">
                    <input
                        type="password"
                        name="confirm_password"
                        id="confirm_password"
                        class="form-control"
                        placeholder="Confirm new password"
                        minlength="8"
                        autocomplete="new-password"
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

            <button type="submit" class="btn btn-orange w-100 mb-3">
                <i class="bi bi-shield-lock"></i>
                Change Password
            </button>

            <a href="dashboard.php" class="btn btn-back w-100">
                <i class="bi bi-arrow-left"></i>
                Back to Dashboard
            </a>

        </form>

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