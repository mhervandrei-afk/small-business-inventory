<?php
session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

require_once __DIR__ . "/config/database.php";

// Verify current user
$userId = (int) $_SESSION["user_id"];

$stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");

if (!$stmt) {
    error_log("User verification prepare failed: " . $conn->error);
    http_response_code(500);
    exit("Something went wrong. Please try again later.");
}

$stmt->bind_param("i", $userId);
$stmt->execute();

$result = $stmt->get_result();
$currentUser = $result->fetch_assoc();

$stmt->close();

if (!$currentUser) {
    $_SESSION = [];

    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            "",
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }

    session_destroy();

    header("Location: login.php");
    exit;
}

$userRole = strtolower(trim((string) $currentUser["role"]));

if (!in_array($userRole, ["administrator", "owner"], true)) {
    header("Location: dashboard.php");
    exit;
}

$_SESSION["user_role"] = $userRole;

// Get all products
$sql = "SELECT id, product_name, category, price, stock
        FROM products
        ORDER BY product_name ASC";

$result = $conn->query($sql);

if (!$result) {
    error_log("Inventory query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load inventory. Please try again later.");
}

// Calculate inventory summary
$totalProducts = 0;
$totalStock = 0;
$lowStock = 0;

$products = [];

while ($row = $result->fetch_assoc()) {
    $products[] = $row;

    $stock = (int) $row["stock"];

    $totalProducts++;
    $totalStock += $stock;

    if ($stock <= 5) {
        $lowStock++;
    }
}

$result->free();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Inventory | Small Business System</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">

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

        .page-title {
            color: #172033;
            font-weight: bold;
        }

        .summary-card {
            background: white;
            border: none;
            border-radius: 12px;
            padding: 22px;
            box-shadow: 0 3px 12px rgba(0,0,0,0.05);
        }

        .summary-card h2 {
            color: #ff9418;
            font-weight: bold;
        }

        .inventory-table {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 3px 12px rgba(0,0,0,0.05);
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
    </style>
</head>

<body>

<nav class="navbar navbar-expand-lg">
    <div class="container">
        <a class="navbar-brand" href="dashboard.php">
            Small Business System
        </a>

        <div>
            <a href="dashboard.php" class="btn btn-outline-light btn-sm">
                Dashboard
            </a>

            <a href="logout.php" class="btn btn-orange btn-sm">
                Logout
            </a>
        </div>
    </div>
</nav>

<div class="container py-4">

    <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
            <h2 class="page-title">Inventory Management</h2>
            <p class="text-muted mb-0">
                Monitor your product stocks and inventory levels.
            </p>
        </div>

        <a href="products.php" class="btn btn-orange">
            Manage Products
        </a>
    </div>

    <!-- Summary Cards -->
    <div class="row g-3 mb-4">

        <div class="col-md-4">
            <div class="summary-card">
                <p class="text-muted mb-1">Total Products</p>
                <h2><?= $totalProducts ?></h2>
            </div>
        </div>

        <div class="col-md-4">
            <div class="summary-card">
                <p class="text-muted mb-1">Total Stock Quantity</p>
                <h2><?= $totalStock ?></h2>
            </div>
        </div>

        <div class="col-md-4">
            <div class="summary-card">
                <p class="text-muted mb-1">Low Stock Products</p>
                <h2><?= $lowStock ?></h2>
                <small class="text-muted">Stock quantity of 5 or below</small>
            </div>
        </div>

    </div>

    <!-- Inventory Table -->
    <div class="inventory-table">

        <h5 class="mb-3">Inventory List</h5>

        <div class="table-responsive">
            <table class="table table-hover align-middle">

                <thead class="table-dark">
                    <tr>
                        <th>ID</th>
                        <th>Product Name</th>
                        <th>Category</th>
                        <th>Price</th>
                        <th>Stock Quantity</th>
                        <th>Status</th>
                    </tr>
                </thead>

                <tbody>

                <?php if (count($products) > 0): ?>

                    <?php foreach ($products as $product): ?>

                        <tr>
                            <td><?= (int) $product["id"] ?></td>

                            <td>
                                <?= htmlspecialchars((string) $product["product_name"], ENT_QUOTES, "UTF-8") ?>
                            </td>

                            <td>
                                <?= htmlspecialchars((string) $product["category"], ENT_QUOTES, "UTF-8") ?>
                            </td>

                            <td>
                                ₱<?= number_format((float) $product["price"], 2) ?>
                            </td>

                            <td>
                                <?= (int) $product["stock"] ?>
                            </td>

                            <td>
                                <?php if ((int) $product["stock"] <= 0): ?>
                                    <span class="badge bg-danger">Out of Stock</span>

                                <?php elseif ((int) $product["stock"] <= 5): ?>
                                    <span class="badge bg-warning text-dark">Low Stock</span>

                                <?php else: ?>
                                    <span class="badge bg-success">In Stock</span>
                                <?php endif; ?>
                            </td>
                        </tr>

                    <?php endforeach; ?>

                <?php else: ?>

                    <tr>
                        <td colspan="6" class="text-center text-muted py-4">
                            No products found. Add products first.
                        </td>
                    </tr>

                <?php endif; ?>

                </tbody>
            </table>
        </div>

    </div>

</div>

</body>
</html>