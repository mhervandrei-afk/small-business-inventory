<?php
session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

require_once __DIR__ . "/config/database.php";

$userId = (int) $_SESSION["user_id"];

$stmt = $conn->prepare(
    "SELECT name, email, role FROM users WHERE id = ?"
);

if (!$stmt) {
    die("Unable to load profile. Please try again later.");
}

$stmt->bind_param("i", $userId);
$stmt->execute();

$result = $stmt->get_result();
$user = $result->fetch_assoc();

$stmt->close();

if (!$user) {
    $_SESSION = [];
    session_destroy();

    header("Location: login.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>My Profile | Small Business System</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

    <style>
        body {
            background: #f4f5f7;
            font-family: Arial, sans-serif;
        }

        .navbar {
            background: #172033;
        }

        .navbar-brand {
            color: white;
            font-weight: bold;
        }

        .profile-container {
            max-width: 650px;
            margin: 40px auto;
        }

        .profile-card {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 3px 12px rgba(0,0,0,0.05);
        }

        .profile-icon {
            font-size: 75px;
            color: #ff9418;
        }

        .section-title {
            color: #172033;
            font-weight: bold;
        }

        .info-box {
            background: #f4f5f7;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
        }

        .btn-orange {
            background: #ff9418;
            color: white;
            border: none;
        }

        .btn-orange:hover {
            background: #e68108;
            color: white;
        }

        .btn-dark-blue {
            background: #172033;
            color: white;
        }

        .btn-dark-blue:hover {
            background: #263653;
            color: white;
        }
    </style>
</head>

<body>

<nav class="navbar">
    <div class="container">
        <a class="navbar-brand text-decoration-none" href="dashboard.php">
            Small Business System
        </a>

        <a href="logout.php" class="btn btn-orange btn-sm">
            Logout
        </a>
    </div>
</nav>

<div class="container profile-container">

    <div class="profile-card text-center">

        <i class="bi bi-person-circle profile-icon"></i>

        <h3 class="section-title mt-2">My Profile</h3>

        <p class="text-muted">
            View your account information and manage your security settings.
        </p>

        <hr>

        <h5 class="section-title text-start mb-3">
            Account Information
        </h5>

        <div class="info-box text-start">
            <small class="text-muted">Full Name</small>
            <h6 class="mb-0">
                <?= htmlspecialchars($user["name"], ENT_QUOTES, "UTF-8") ?>
            </h6>
        </div>

        <div class="info-box text-start">
            <small class="text-muted">Email Address</small>
            <h6 class="mb-0">
                <?= htmlspecialchars($user["email"], ENT_QUOTES, "UTF-8") ?>
            </h6>
        </div>

        <div class="info-box text-start">
            <small class="text-muted">Account Role</small>
            <h6 class="mb-0">
                <?= htmlspecialchars(ucfirst(strtolower($user["role"])), ENT_QUOTES, "UTF-8") ?>
            </h6>
        </div>

        <hr>

        <h5 class="section-title text-start mb-3">
            Security Settings
        </h5>

        <a href="change_password.php" class="btn btn-orange w-100 mb-3">
            <i class="bi bi-shield-lock"></i>
            Change Password
        </a>

        <a href="dashboard.php" class="btn btn-dark-blue w-100">
            <i class="bi bi-arrow-left"></i>
            Back to Dashboard
        </a>

    </div>

</div>

</body>
</html>