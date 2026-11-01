<?php
session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit();
}

require_once __DIR__ . "/config/database.php";

$currentUserId = (int)$_SESSION["user_id"];

$message = "";
$messageType = "success";
$search = trim(is_string($_GET["search"] ?? "") ? $_GET["search"] : "");
$editId = filter_var($_GET["edit"] ?? 0, FILTER_VALIDATE_INT);
$editId = $editId !== false ? max(0, $editId) : 0;

// HTML ESCAPING
function e($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES, "UTF-8");
}

// VERIFY ADMINISTRATOR ROLE FROM DATABASE
$authStmt = $conn->prepare("SELECT role FROM users WHERE id = ?");

if (!$authStmt) {
    exit("Unable to verify account. Please check your database connection.");
}

$authStmt->bind_param("i", $currentUserId);

if (!$authStmt->execute()) {
    exit("Unable to verify account.");
}

$currentUser = $authStmt->get_result()->fetch_assoc();
$authStmt->close();

if (!$currentUser || strtolower($currentUser["role"]) !== "administrator") {
    $_SESSION = [];
    session_destroy();
    header("Location: login.php");
    exit();
}

// CSRF TOKEN
if (
    empty($_SESSION["csrf_token"]) ||
    !is_string($_SESSION["csrf_token"])
) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

function validToken(): bool {
    return isset($_POST["csrf_token"], $_SESSION["csrf_token"])
        && is_string($_POST["csrf_token"])
        && is_string($_SESSION["csrf_token"])
        && hash_equals($_SESSION["csrf_token"], $_POST["csrf_token"]);
}

function countAdministrators($conn): int {
    $result = $conn->query(
        "SELECT COUNT(*) AS total FROM users WHERE LOWER(role) = 'administrator'"
    );

    if (!$result) {
        throw new RuntimeException("Unable to count administrator accounts.");
    }

    $row = $result->fetch_assoc();
    return (int)($row["total"] ?? 0);
}

// PROCESS POST REQUESTS
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    if (!validToken()) {
        $message = "Invalid request. Please refresh the page.";
        $messageType = "danger";

    } else {

        try {

            // ADD USER
            if (isset($_POST["add_user"])) {

                $name = trim(is_string($_POST["name"] ?? "") ? $_POST["name"] : "");
                $email = strtolower(trim(is_string($_POST["email"] ?? "") ? $_POST["email"] : ""));
                $password = is_string($_POST["password"] ?? "") ? $_POST["password"] : "";
                $role = strtolower(trim(is_string($_POST["role"] ?? "") ? $_POST["role"] : ""));

                if ($name === "" || $email === "" || $password === "") {
                    throw new InvalidArgumentException("Please complete all required fields.");
                }

                if (strlen($name) > 100) {
                    throw new InvalidArgumentException("Name must not exceed 100 characters.");
                }

                if (strlen($email) > 150 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    throw new InvalidArgumentException("Please enter a valid email address.");
                }

                if (strlen($password) < 8 || strlen($password) > 4096) {
                    throw new InvalidArgumentException("Password must be between 8 and 4096 characters.");
                }

                if (!in_array($role, ["owner", "administrator"], true)) {
                    throw new InvalidArgumentException("Please select a valid account role.");
                }

                $check = $conn->prepare("SELECT id FROM users WHERE email = ?");

                if (!$check) {
                    throw new RuntimeException("Unable to check email address.");
                }

                $check->bind_param("s", $email);

                if (!$check->execute()) {
                    $check->close();
                    throw new RuntimeException("Unable to check email address.");
                }

                $exists = $check->get_result()->num_rows > 0;
                $check->close();

                if ($exists) {
                    throw new InvalidArgumentException("Email address is already registered.");
                }

                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

                $stmt = $conn->prepare(
                    "INSERT INTO users (name, email, password, role)
                     VALUES (?, ?, ?, ?)"
                );

                if (!$stmt) {
                    throw new RuntimeException("Unable to prepare account creation.");
                }

                $stmt->bind_param("ssss", $name, $email, $hashedPassword, $role);

                if (!$stmt->execute()) {
                    $stmt->close();
                    throw new RuntimeException("Unable to create user account.");
                }

                $stmt->close();
                $message = "User account created successfully.";
            }

            // DELETE USER
            elseif (isset($_POST["delete_user"])) {

                $deleteId = filter_var($_POST["user_id"] ?? 0, FILTER_VALIDATE_INT);

                if (!$deleteId || $deleteId <= 0) {
                    throw new InvalidArgumentException("Invalid user account.");
                }

                if ($deleteId === $currentUserId) {
                    throw new InvalidArgumentException("You cannot delete your own account.");
                }

                $stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");

                if (!$stmt) {
                    throw new RuntimeException("Unable to find user account.");
                }

                $stmt->bind_param("i", $deleteId);

                if (!$stmt->execute()) {
                    $stmt->close();
                    throw new RuntimeException("Unable to find user account.");
                }

                $target = $stmt->get_result()->fetch_assoc();
                $stmt->close();

                if (!$target) {
                    throw new InvalidArgumentException("User account not found.");
                }

                if (
                    strtolower($target["role"]) === "administrator"
                    && countAdministrators($conn) <= 1
                ) {
                    throw new InvalidArgumentException(
                        "You cannot delete the last Administrator account."
                    );
                }

                $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");

                if (!$stmt) {
                    throw new RuntimeException("Unable to prepare account deletion.");
                }

                $stmt->bind_param("i", $deleteId);

                if (!$stmt->execute() || $stmt->affected_rows !== 1) {
                    $stmt->close();
                    throw new RuntimeException("Unable to delete user account.");
                }

                $stmt->close();
                $message = "User account deleted successfully.";
            }

            // UPDATE USER
            elseif (isset($_POST["update_user"])) {

                $editUserId = filter_var($_POST["user_id"] ?? 0, FILTER_VALIDATE_INT);
                $name = trim(is_string($_POST["name"] ?? "") ? $_POST["name"] : "");
                $email = strtolower(trim(is_string($_POST["email"] ?? "") ? $_POST["email"] : ""));
                $role = strtolower(trim(is_string($_POST["role"] ?? "") ? $_POST["role"] : ""));

                if (!$editUserId || $editUserId <= 0 || $name === "" || $email === "") {
                    throw new InvalidArgumentException("Please complete all required fields.");
                }

                if (strlen($name) > 100) {
                    throw new InvalidArgumentException("Name must not exceed 100 characters.");
                }

                if (strlen($email) > 150 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    throw new InvalidArgumentException("Please enter a valid email address.");
                }

                if (!in_array($role, ["owner", "administrator"], true)) {
                    throw new InvalidArgumentException("Please select a valid account role.");
                }

                if ($editUserId === $currentUserId) {
                    throw new InvalidArgumentException("You cannot change your own account role here.");
                }

                $stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");

                if (!$stmt) {
                    throw new RuntimeException("Unable to find user account.");
                }

                $stmt->bind_param("i", $editUserId);

                if (!$stmt->execute()) {
                    $stmt->close();
                    throw new RuntimeException("Unable to find user account.");
                }

                $target = $stmt->get_result()->fetch_assoc();
                $stmt->close();

                if (!$target) {
                    throw new InvalidArgumentException("User account not found.");
                }

                if (
                    strtolower($target["role"]) === "administrator"
                    && $role !== "administrator"
                    && countAdministrators($conn) <= 1
                ) {
                    throw new InvalidArgumentException(
                        "You cannot remove the role of the last Administrator."
                    );
                }

                $check = $conn->prepare(
                    "SELECT id FROM users WHERE email = ? AND id != ?"
                );

                if (!$check) {
                    throw new RuntimeException("Unable to check email address.");
                }

                $check->bind_param("si", $email, $editUserId);

                if (!$check->execute()) {
                    $check->close();
                    throw new RuntimeException("Unable to check email address.");
                }

                $emailExists = $check->get_result()->num_rows > 0;
                $check->close();

                if ($emailExists) {
                    throw new InvalidArgumentException("Email address is already in use.");
                }

                $stmt = $conn->prepare(
                    "UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?"
                );

                if (!$stmt) {
                    throw new RuntimeException("Unable to prepare account update.");
                }

                $stmt->bind_param("sssi", $name, $email, $role, $editUserId);

                if (!$stmt->execute()) {
                    $stmt->close();
                    throw new RuntimeException("Unable to update user account.");
                }

                $stmt->close();
                $message = "User account updated successfully.";
                $editId = 0;
            }

        } catch (InvalidArgumentException $exception) {
            $message = $exception->getMessage();
            $messageType = "danger";

        } catch (Throwable $exception) {
            $message = "An error occurred while processing the request. Please try again.";
            $messageType = "danger";
            error_log($exception->getMessage());
        }

        $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
    }
}

// GET USER TO EDIT
$editUser = null;

if ($editId > 0) {
    $stmt = $conn->prepare(
        "SELECT id, name, email, role FROM users WHERE id = ?"
    );

    if ($stmt) {
        $stmt->bind_param("i", $editId);
        $stmt->execute();
        $editUser = $stmt->get_result()->fetch_assoc();
        $stmt->close();
    }
}

// SEARCH USERS
if ($search !== "") {
    $searchTerm = "%" . $search . "%";

    $stmt = $conn->prepare(
        "SELECT id, name, email, role
         FROM users
         WHERE name LIKE ? OR email LIKE ?
         ORDER BY id DESC"
    );

    if (!$stmt) {
        exit("Unable to load user records.");
    }

    $stmt->bind_param("ss", $searchTerm, $searchTerm);

    if (!$stmt->execute()) {
        $stmt->close();
        exit("Unable to load user records.");
    }

    $result = $stmt->get_result();

} else {
    $result = $conn->query(
        "SELECT id, name, email, role FROM users ORDER BY id DESC"
    );

    if (!$result) {
        exit("Unable to load user records.");
    }
}

$totalUsers = $result->num_rows;
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>User Management | Small Business System</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

    <!-- BOOTSTRAP ICONS: REQUIRED FOR EYE ICON -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

    <style>
        body {
            background: #f3f5f9;
            font-family: Arial, sans-serif;
        }

        .navbar {
            background: #172033;
        }

        .navbar-brand {
            color: white;
            font-weight: bold;
        }

        .main-container {
            margin-top: 35px;
            margin-bottom: 40px;
        }

        .page-title {
            color: #172033;
            font-weight: bold;
        }

        .content-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 3px 12px rgba(0,0,0,0.06);
            margin-bottom: 25px;
        }

        .table thead {
            background: #172033;
            color: white;
        }

        .role-badge {
            background: #fff0dc;
            color: #d97706;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
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

        .back-btn {
            background: #172033;
            color: white;
        }

        .back-btn:hover {
            background: #ff9418;
            color: white;
        }

        /* PASSWORD SHOW / HIDE */

        .password-wrapper {
            position: relative;
            width: 100%;
        }

        .password-wrapper input {
            padding-right: 48px;
        }

        .toggle-password {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            border: none;
            background: transparent;
            color: #888;
            font-size: 20px;
            cursor: pointer;
            padding: 3px;
            line-height: 1;
        }

        .toggle-password:hover {
            color: #172033;
        }
    </style>
</head>

<body>

<nav class="navbar navbar-dark">
    <div class="container">
        <a class="navbar-brand" href="dashboard.php">
            Small Business System
        </a>

        <a href="logout.php" class="btn btn-outline-light btn-sm">
            Logout
        </a>
    </div>
</nav>

<div class="container main-container">

    <div class="d-flex justify-content-between align-items-center mb-4 flex-wrap gap-2">
        <div>
            <h2 class="page-title">User Management</h2>
            <p class="text-muted mb-0">
                Create, search, edit, and manage user accounts.
            </p>
        </div>

        <a href="dashboard.php" class="btn back-btn">
            Back to Dashboard
        </a>
    </div>

    <?php if ($message !== ""): ?>
        <div class="alert alert-<?= e($messageType) ?> alert-dismissible fade show">
            <?= e($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <!-- ADD USER -->
    <div class="content-card">

        <h5 class="fw-bold mb-3">Add New User</h5>

        <form method="POST" action="users.php">

            <input type="hidden" name="csrf_token"
                   value="<?= e($_SESSION["csrf_token"]) ?>">

            <div class="row g-3">

                <div class="col-md-6">
                    <label class="form-label">Full Name</label>
                    <input type="text" name="name" maxlength="100"
                           class="form-control" required>
                </div>

                <div class="col-md-6">
                    <label class="form-label">Email Address</label>
                    <input type="email" name="email" maxlength="150"
                           class="form-control" required>
                </div>

                <div class="col-md-6">
                    <label class="form-label">Password</label>

                    <div class="password-wrapper">
                        <input
                            type="password"
                            name="password"
                            id="newUserPassword"
                            class="form-control"
                            minlength="8"
                            maxlength="4096"
                            required
                        >

                        <button
                            type="button"
                            class="toggle-password"
                            onclick="togglePassword('newUserPassword', this)"
                            aria-label="Show password"
                        >
                            <i class="bi bi-eye-slash"></i>
                        </button>
                    </div>

                    <small class="text-muted">Minimum 8 characters.</small>
                </div>

                <div class="col-md-6">
                    <label class="form-label">Account Role</label>

                    <select name="role" class="form-select" required>
                        <option value="owner">Owner</option>
                        <option value="administrator">Administrator</option>
                    </select>
                </div>

            </div>

            <button type="submit" name="add_user" class="btn btn-orange mt-3">
                Add User Account
            </button>

        </form>

    </div>

    <!-- EDIT USER -->
    <?php if ($editUser): ?>

        <div class="content-card">

            <h5 class="fw-bold mb-3">Edit User Account</h5>

            <form method="POST" action="users.php?search=<?= urlencode($search) ?>">

                <input type="hidden" name="csrf_token"
                       value="<?= e($_SESSION["csrf_token"]) ?>">

                <input type="hidden" name="user_id"
                       value="<?= (int)$editUser["id"] ?>">

                <div class="mb-3">
                    <label class="form-label">Full Name</label>

                    <input type="text" name="name" maxlength="100"
                           class="form-control"
                           value="<?= e($editUser["name"]) ?>" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Email Address</label>

                    <input type="email" name="email" maxlength="150"
                           class="form-control"
                           value="<?= e($editUser["email"]) ?>" required>
                </div>

                <div class="mb-3">
                    <label class="form-label">Account Role</label>

                    <?php if ((int)$editUser["id"] === $currentUserId): ?>

                        <input type="text" class="form-control"
                               value="Administrator" disabled>

                        <small class="text-muted">
                            You cannot change your own role.
                        </small>

                    <?php else: ?>

                        <select name="role" class="form-select" required>
                            <option value="owner"
                                <?= strtolower($editUser["role"]) === "owner" ? "selected" : "" ?>>
                                Owner
                            </option>

                            <option value="administrator"
                                <?= strtolower($editUser["role"]) === "administrator" ? "selected" : "" ?>>
                                Administrator
                            </option>
                        </select>

                    <?php endif; ?>
                </div>

                <button type="submit" name="update_user" class="btn btn-orange">
                    Save Changes
                </button>

                <a href="users.php?search=<?= urlencode($search) ?>"
                   class="btn btn-secondary">
                    Cancel
                </a>

            </form>

        </div>

    <?php elseif ($editId > 0): ?>

        <div class="alert alert-warning">
            User account not found.
        </div>

    <?php endif; ?>

    <!-- USER LIST -->
    <div class="content-card">

        <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-3">

            <h5 class="fw-bold mb-0">Registered Users</h5>

            <span class="badge text-bg-dark">
                Total Users: <?= (int)$totalUsers ?>
            </span>

        </div>

        <form method="GET" action="users.php" class="row g-2 mb-4">

            <div class="col-md-9">
                <input type="text" name="search" class="form-control"
                       placeholder="Search by name or email..."
                       value="<?= e($search) ?>">
            </div>

            <div class="col-md-3 d-grid">
                <button type="submit" class="btn btn-orange">
                    Search Users
                </button>
            </div>

        </form>

        <?php if ($search !== ""): ?>
            <p class="text-muted">
                Search results for: <strong><?= e($search) ?></strong>
                <a href="users.php" class="ms-2">Clear Search</a>
            </p>
        <?php endif; ?>

        <div class="table-responsive">

            <table class="table table-hover align-middle">

                <thead>
                    <tr>
                        <th>User ID</th>
                        <th>Name</th>
                        <th>Email Address</th>
                        <th>Role</th>
                        <th>Account</th>
                        <th>Actions</th>
                    </tr>
                </thead>

                <tbody>

                <?php if ($totalUsers > 0): ?>

                    <?php while ($user = $result->fetch_assoc()): ?>

                        <tr>
                            <td><?= (int)$user["id"] ?></td>

                            <td class="fw-semibold">
                                <?= e($user["name"]) ?>
                            </td>

                            <td><?= e($user["email"]) ?></td>

                            <td>
                                <span class="role-badge">
                                    <?= e(ucfirst($user["role"])) ?>
                                </span>
                            </td>

                            <td>
                                <span class="badge bg-success">
                                    Registered
                                </span>
                            </td>

                            <td>
                                <div class="d-flex gap-2">

                                    <a href="users.php?edit=<?= (int)$user["id"] ?>&search=<?= urlencode($search) ?>"
                                       class="btn btn-sm btn-primary">
                                        Edit
                                    </a>

                                    <?php if ((int)$user["id"] !== $currentUserId): ?>

                                        <form method="POST"
                                              action="users.php?search=<?= urlencode($search) ?>"
                                              onsubmit="return confirm('Are you sure you want to delete this user account?');">

                                            <input type="hidden" name="csrf_token"
                                                   value="<?= e($_SESSION["csrf_token"]) ?>">

                                            <input type="hidden" name="user_id"
                                                   value="<?= (int)$user["id"] ?>">

                                            <button type="submit" name="delete_user"
                                                    class="btn btn-sm btn-danger">
                                                Delete
                                            </button>

                                        </form>

                                    <?php else: ?>

                                        <button class="btn btn-sm btn-secondary" disabled>
                                            Current Account
                                        </button>

                                    <?php endif; ?>

                                </div>
                            </td>
                        </tr>

                    <?php endwhile; ?>

                <?php else: ?>

                    <tr>
                        <td colspan="6" class="text-center text-muted py-4">
                            No registered users found.
                        </td>
                    </tr>

                <?php endif; ?>

                </tbody>

            </table>

        </div>

    </div>

</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

<script>
function togglePassword(inputId, button) {

    const input = document.getElementById(inputId);
    const icon = button.querySelector("i");

    if (!input || !icon) {
        return;
    }

    if (input.type === "password") {

        input.type = "text";

        icon.classList.replace("bi-eye-slash", "bi-eye");

        button.setAttribute("aria-label", "Hide password");

    } else {

        input.type = "password";

        icon.classList.replace("bi-eye", "bi-eye-slash");

        button.setAttribute("aria-label", "Show password");
    }
}
</script>

</body>
</html>