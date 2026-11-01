<?php
session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

// Database connection — kailangang mauna bago gamitin ang $conn
require_once __DIR__ . "/config/database.php";

// Kunin ang kasalukuyang user mula sa database
$userId = (int)$_SESSION["user_id"];

$stmt = $conn->prepare(
    "SELECT name, role FROM users WHERE id = ?"
);

if (!$stmt) {
    die("Database query error: " . $conn->error);
}

$stmt->bind_param("i", $userId);
$stmt->execute();

$currentUser = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$currentUser) {
    session_destroy();
    header("Location: login.php");
    exit;
}

$userName = $currentUser["name"];
$userRole = strtolower(trim($currentUser["role"]));

$_SESSION["user_name"] = $userName;
$_SESSION["user_role"] = $userRole;

$isAdministrator = ($userRole === "administrator");

// Total products
$productResult = $conn->query(
    "SELECT COUNT(*) AS total FROM products"
);
$totalProducts = $productResult->fetch_assoc()["total"];

// Total stock
$stockResult = $conn->query(
    "SELECT COALESCE(SUM(stock), 0) AS total FROM products"
);
$totalStock = $stockResult->fetch_assoc()["total"];

// Low stock products
$lowStockResult = $conn->query(
    "SELECT COUNT(*) AS total FROM products WHERE stock <= 5"
);
$lowStock = $lowStockResult->fetch_assoc()["total"];

// Total sales
$salesResult = $conn->query(
    "SELECT COALESCE(SUM(total_amount), 0) AS total FROM sales"
);
$totalSales = $salesResult->fetch_assoc()["total"];

// Recent sales
$recentSales = $conn->query(
    "SELECT product_name, quantity, total_amount, sale_date
     FROM sales
     ORDER BY sale_date DESC, id DESC
     LIMIT 5"
);

// Recent stock movements
$recentMovements = $conn->query(
    "SELECT product_name, movement_type, quantity,
            previous_stock, new_stock, created_at
     FROM stock_movements
     ORDER BY created_at DESC, id DESC
     LIMIT 5"
);
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Dashboard | Small Business System</title>

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

        .welcome {
            background: #172033;
            color: white;
            padding: 30px;
            border-radius: 12px;
        }

        .summary-card {
            background: white;
            border: none;
            border-radius: 12px;
            padding: 22px;
            box-shadow: 0 3px 12px rgba(0,0,0,0.05);
            height: 100%;
        }

        .summary-card h2 {
            color: #ff9418;
            font-weight: bold;
        }

        .feature-card {
            background: white;
            border: none;
            border-radius: 12px;
            padding: 25px;
            height: 100%;
            box-shadow: 0 3px 12px rgba(0,0,0,0.05);
        }

        .feature-card h5 {
            color: #172033;
            font-weight: bold;
        }

        .feature-icon {
            font-size: 30px;
            color: #ff9418;
            margin-bottom: 12px;
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

        .section-title {
            color: #172033;
            font-weight: bold;
        }
    </style>
</head>

<body>

<!-- Navbar -->
<nav class="navbar navbar-expand-lg">
    <div class="container">

        <a class="navbar-brand" href="dashboard.php">
            Small Business System
        </a>

        <div>
            <span class="text-white me-3">
                <?= htmlspecialchars($userName, ENT_QUOTES, "UTF-8") ?>
            </span>

            <a href="logout.php" class="btn btn-orange btn-sm">
                Logout
            </a>
        </div>

    </div>
</nav>

<div class="container py-4">

    <!-- Welcome Section -->
    <div class="welcome mb-4">

        <h2>
            Welcome, <?= htmlspecialchars($userName, ENT_QUOTES, "UTF-8") ?>!
        </h2>

        <p class="mb-0">
            Role:
            <?= htmlspecialchars(ucfirst($userRole), ENT_QUOTES, "UTF-8") ?>

            <br>

            Manage your products, inventory, and business sales in one place.
        </p>

    </div>

    <!-- Summary Cards -->
    <h4 class="section-title mb-3">Business Overview</h4>

    <div class="row g-3 mb-4">

        <div class="col-md-3">
            <div class="summary-card">
                <p class="text-muted">Total Products</p>
                <h2><?= (int)$totalProducts ?></h2>
                <small>Registered products</small>
            </div>
        </div>

        <div class="col-md-3">
            <div class="summary-card">
                <p class="text-muted">Total Stock</p>
                <h2><?= (int)$totalStock ?></h2>
                <small>Available stock quantity</small>
            </div>
        </div>

        <div class="col-md-3">
            <div class="summary-card">
                <p class="text-muted">Low Stock</p>
                <h2><?= (int)$lowStock ?></h2>
                <small>Products with 5 or fewer stocks</small>
            </div>
        </div>

        <div class="col-md-3">
            <div class="summary-card">
                <p class="text-muted">Total Sales</p>
                <h2>₱<?= number_format((float)$totalSales, 2) ?></h2>
                <small>Recorded sales amount</small>
            </div>
        </div>

    </div>

    <!-- Navigation Cards -->
    <h4 class="section-title mb-3">System Management</h4>

    <div class="row g-3 mb-4">

        <!-- Products -->
        <div class="col-md-3">
            <div class="feature-card">

                <div class="feature-icon">
                    <i class="bi bi-box-seam"></i>
                </div>

                <h5>Products Management</h5>

                <p class="text-muted">
                    Add, edit, delete, and view your business products.
                </p>

                <a href="products.php" class="btn btn-orange">
                    Manage Products
                </a>

            </div>
        </div>

        <!-- Inventory -->
        <div class="col-md-3">
            <div class="feature-card">

                <div class="feature-icon">
                    <i class="bi bi-clipboard-data"></i>
                </div>

                <h5>Inventory Management</h5>

                <p class="text-muted">
                    Monitor available stocks and identify low-stock products.
                </p>

                <a href="inventory.php" class="btn btn-orange">
                    View Inventory
                </a>

            </div>
        </div>

        <!-- Sales -->
        <div class="col-md-3">
            <div class="feature-card">

                <div class="feature-icon">
                    <i class="bi bi-cart-check"></i>
                </div>

                <h5>Sales Management</h5>

                <p class="text-muted">
                    Record transactions and review your sales history.
                </p>

                <a href="sales.php" class="btn btn-orange">
                    Manage Sales
                </a>

            </div>
        </div>

        <!-- Reports -->
        <div class="col-md-3">
            <div class="feature-card">

                <div class="feature-icon">
                    <i class="bi bi-bar-chart"></i>
                </div>

                <h5>Reports Management</h5>

                <p class="text-muted">
                    View daily sales reports and business performance.
                </p>

                <a href="reports.php" class="btn btn-orange">
                    View Reports
                </a>

            </div>
        </div>

        <!-- Stock History -->
        <div class="col-md-3">
            <div class="feature-card">

                <div class="feature-icon">
                    <i class="bi bi-clock-history"></i>
                </div>

                <h5>Stock Movement History</h5>

                <p class="text-muted">
                    Track stock additions, removals, and previous stock records.
                </p>

                <a href="stock_history.php" class="btn btn-orange">
                    View Stock History
                </a>

            </div>
        </div>

        <!-- User Management: Administrator Only -->
        <?php if ($isAdministrator): ?>

        <div class="col-md-3">
            <div class="feature-card">

                <div class="feature-icon">
                    <i class="bi bi-people"></i>
                </div>

                <h5>User Management</h5>

                <p class="text-muted">
                    View, add, edit, and delete user accounts.
                </p>

                <a href="users.php" class="btn btn-orange">
                    Manage Users
                </a>

            </div>
        </div>

        <?php endif; ?>

        <!-- Profile -->
        <div class="col-md-3">
            <div class="feature-card">

                <div class="feature-icon">
                    <i class="bi bi-person-circle"></i>
                </div>

                <h5>My Profile</h5>

                <p class="text-muted">
                    View your account information and manage your password.
                </p>

                <a href="profile.php" class="btn btn-orange">
                    View Profile
                </a>

            </div>
        </div>

    </div>

    <!-- Recent Sales -->
    <div class="summary-card mb-4">

        <h5 class="section-title mb-3">Recent Sales</h5>

        <div class="table-responsive">

            <table class="table table-hover align-middle">

                <thead class="table-dark">
                    <tr>
                        <th>Product</th>
                        <th>Quantity</th>
                        <th>Total Amount</th>
                        <th>Date</th>
                    </tr>
                </thead>

                <tbody>

                <?php if ($recentSales && $recentSales->num_rows > 0): ?>

                    <?php while ($sale = $recentSales->fetch_assoc()): ?>

                        <tr>

                            <td>
                                <?= htmlspecialchars($sale["product_name"] ?? "N/A", ENT_QUOTES, "UTF-8") ?>
                            </td>

                            <td>
                                <?= (int)$sale["quantity"] ?>
                            </td>

                            <td>
                                ₱<?= number_format((float)$sale["total_amount"], 2) ?>
                            </td>

                            <td>
                                <?= !empty($sale["sale_date"])
                                    ? date("M d, Y h:i A", strtotime($sale["sale_date"]))
                                    : "N/A" ?>
                            </td>

                        </tr>

                    <?php endwhile; ?>

                <?php else: ?>

                    <tr>
                        <td colspan="4" class="text-center text-muted py-3">
                            No sales recorded yet.
                        </td>
                    </tr>

                <?php endif; ?>

                </tbody>

            </table>

        </div>

    </div>

    <!-- Recent Stock Movements -->
    <div class="summary-card">

        <div class="d-flex justify-content-between align-items-center mb-3">

            <h5 class="section-title mb-0">
                Recent Stock Movements
            </h5>

            <a href="stock_history.php" class="btn btn-orange btn-sm">
                View All
            </a>

        </div>

        <div class="table-responsive">

            <table class="table table-hover align-middle">

                <thead class="table-dark">
                    <tr>
                        <th>Product</th>
                        <th>Movement</th>
                        <th>Quantity</th>
                        <th>Previous Stock</th>
                        <th>New Stock</th>
                        <th>Date</th>
                    </tr>
                </thead>

                <tbody>

                <?php if ($recentMovements && $recentMovements->num_rows > 0): ?>

                    <?php while ($movement = $recentMovements->fetch_assoc()): ?>

                        <tr>

                            <td>
                                <?= htmlspecialchars($movement["product_name"], ENT_QUOTES, "UTF-8") ?>
                            </td>

                            <td>

                                <?php if ($movement["movement_type"] === "Add Stock"): ?>

                                    <span class="badge bg-success">
                                        Add Stock
                                    </span>

                                <?php else: ?>

                                    <span class="badge bg-danger">
                                        Remove Stock
                                    </span>

                                <?php endif; ?>

                            </td>

                            <td>
                                <?= (int)$movement["quantity"] ?>
                            </td>

                            <td>
                                <?= (int)$movement["previous_stock"] ?>
                            </td>

                            <td>
                                <?= (int)$movement["new_stock"] ?>
                            </td>

                            <td>
                                <?= date("M d, Y h:i A", strtotime($movement["created_at"])) ?>
                            </td>

                        </tr>

                    <?php endwhile; ?>

                <?php else: ?>

                    <tr>
                        <td colspan="6" class="text-center text-muted py-3">
                            No stock movements recorded yet.
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