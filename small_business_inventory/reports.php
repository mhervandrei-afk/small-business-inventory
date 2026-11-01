<?php
date_default_timezone_set("Asia/Manila");
session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

require_once __DIR__ . "/config/database.php";

// Safe output function
function escape($value) {
    return htmlspecialchars((string) $value, ENT_QUOTES, "UTF-8");
}

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

$userResult = $stmt->get_result();
$currentUser = $userResult->fetch_assoc();

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

// Total sales revenue
$totalSalesResult = $conn->query(
    "SELECT COALESCE(SUM(total_amount), 0) AS total
     FROM sales"
);

if (!$totalSalesResult) {
    error_log("Total sales query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load sales reports.");
}

$totalSales = $totalSalesResult->fetch_assoc()["total"];
$totalSalesResult->free();

// Total transactions
$totalTransactionsResult = $conn->query(
    "SELECT COUNT(*) AS total
     FROM sales"
);

if (!$totalTransactionsResult) {
    error_log("Transaction count query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load sales reports.");
}

$totalTransactions = $totalTransactionsResult->fetch_assoc()["total"];
$totalTransactionsResult->free();

// Total products sold
$totalItemsResult = $conn->query(
    "SELECT COALESCE(SUM(quantity), 0) AS total
     FROM sales"
);

if (!$totalItemsResult) {
    error_log("Items sold query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load sales reports.");
}

$totalItemsSold = $totalItemsResult->fetch_assoc()["total"];
$totalItemsResult->free();

// Today's sales - Philippine Time (UTC+8)
$todaySalesResult = $conn->query(
    "SELECT COALESCE(SUM(total_amount), 0) AS total
     FROM sales
     WHERE DATE(DATE_ADD(sale_date, INTERVAL 8 HOUR))
           = DATE(DATE_ADD(UTC_TIMESTAMP(), INTERVAL 8 HOUR))"
);

if (!$todaySalesResult) {
    error_log("Today's sales query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load sales reports.");
}

$todaySales = $todaySalesResult->fetch_assoc()["total"];
$todaySalesResult->free();

// Daily sales report - Philippine Time (UTC+8)
$dailyReports = $conn->query(
    "SELECT
        DATE(DATE_ADD(sale_date, INTERVAL 8 HOUR)) AS report_date,
        COUNT(*) AS transactions,
        COALESCE(SUM(quantity), 0) AS items_sold,
        COALESCE(SUM(total_amount), 0) AS daily_total
     FROM sales
     GROUP BY DATE(DATE_ADD(sale_date, INTERVAL 8 HOUR))
     ORDER BY report_date DESC"
);

if (!$dailyReports) {
    error_log("Daily reports query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load daily sales reports.");
}

// Sales history - display Philippine Time (UTC+8)
$salesHistory = $conn->query(
    "SELECT
        id,
        product_name,
        quantity,
        unit_price,
        total_amount,
        DATE_ADD(sale_date, INTERVAL 8 HOUR) AS sale_date
     FROM sales
     ORDER BY sale_date DESC, id DESC"
);

if (!$salesHistory) {
    error_log("Sales history query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load sales history.");
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Reports | Small Business System</title>

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

        .summary-card,
        .content-card {
            background: white;
            border: none;
            border-radius: 12px;
            padding: 22px;
            box-shadow: 0 3px 12px rgba(0,0,0,0.05);
        }

        .summary-card {
            height: 100%;
        }

        .summary-card h2 {
            color: #ff9418;
            font-weight: bold;
        }

        .section-title {
            color: #172033;
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

        @media print {
            body {
                background: white;
            }

            .navbar,
            .print-button {
                display: none !important;
            }

            .container {
                width: 100%;
                max-width: 100%;
            }

            .summary-card,
            .content-card {
                box-shadow: none;
                border: 1px solid #ddd;
                break-inside: avoid;
            }

            .table {
                font-size: 12px;
            }
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
            <h2 class="page-title">Reports Management</h2>
            <p class="text-muted mb-0">
                View your business sales performance and reports.
            </p>
        </div>

        <button
            onclick="window.print()"
            class="btn btn-orange print-button"
            type="button"
        >
            Print Report
        </button>

    </div>

    <!-- Summary Cards -->

    <h5 class="section-title mb-3">Sales Overview</h5>

    <div class="row g-3 mb-4">

        <div class="col-md-3">
            <div class="summary-card">
                <p class="text-muted mb-1">Total Sales Revenue</p>
                <h2>₱<?= number_format((float) $totalSales, 2) ?></h2>
                <small>All recorded sales</small>
            </div>
        </div>

        <div class="col-md-3">
            <div class="summary-card">
                <p class="text-muted mb-1">Total Transactions</p>
                <h2><?= number_format((int) $totalTransactions) ?></h2>
                <small>Recorded transactions</small>
            </div>
        </div>

        <div class="col-md-3">
            <div class="summary-card">
                <p class="text-muted mb-1">Products Sold</p>
                <h2><?= number_format((int) $totalItemsSold) ?></h2>
                <small>Total quantity sold</small>
            </div>
        </div>

        <div class="col-md-3">
            <div class="summary-card">
                <p class="text-muted mb-1">Today's Sales</p>
                <h2>₱<?= number_format((float) $todaySales, 2) ?></h2>
                <small>Sales recorded today</small>
            </div>
        </div>

    </div>

    <!-- Daily Sales Report -->

    <div class="content-card mb-4">

        <h5 class="section-title mb-3">Daily Sales Report</h5>

        <div class="table-responsive">

            <table class="table table-hover align-middle">

                <thead class="table-dark">
                    <tr>
                        <th>Date</th>
                        <th>Transactions</th>
                        <th>Products Sold</th>
                        <th>Daily Revenue</th>
                    </tr>
                </thead>

                <tbody>

                <?php if ($dailyReports->num_rows > 0): ?>

                    <?php while ($report = $dailyReports->fetch_assoc()): ?>

                        <tr>
                            <td>
                                <?php
                                $reportTimestamp = strtotime($report["report_date"]);

                                echo $reportTimestamp !== false
                                    ? escape(date("M d, Y", $reportTimestamp))
                                    : "Invalid date";
                                ?>
                            </td>

                            <td>
                                <?= number_format((int) $report["transactions"]) ?>
                            </td>

                            <td>
                                <?= number_format((int) $report["items_sold"]) ?>
                            </td>

                            <td>
                                <strong>
                                    ₱<?= number_format((float) $report["daily_total"], 2) ?>
                                </strong>
                            </td>
                        </tr>

                    <?php endwhile; ?>

                <?php else: ?>

                    <tr>
                        <td colspan="4" class="text-center text-muted py-4">
                            No daily sales reports available yet.
                        </td>
                    </tr>

                <?php endif; ?>

                </tbody>

            </table>

        </div>

    </div>

    <!-- Sales History -->

    <div class="content-card">

        <h5 class="section-title mb-3">Complete Sales History</h5>

        <div class="table-responsive">

            <table class="table table-hover align-middle">

                <thead class="table-dark">
                    <tr>
                        <th>Sale ID</th>
                        <th>Product Name</th>
                        <th>Quantity</th>
                        <th>Unit Price</th>
                        <th>Total Amount</th>
                        <th>Date</th>
                    </tr>
                </thead>

                <tbody>

                <?php if ($salesHistory->num_rows > 0): ?>

                    <?php while ($sale = $salesHistory->fetch_assoc()): ?>

                        <tr>
                            <td><?= (int) $sale["id"] ?></td>

                            <td>
                                <?= escape($sale["product_name"] ?? "N/A") ?>
                            </td>

                            <td>
                                <?= number_format((int) $sale["quantity"]) ?>
                            </td>

                            <td>
                                ₱<?= number_format((float) $sale["unit_price"], 2) ?>
                            </td>

                            <td>
                                <strong>
                                    ₱<?= number_format((float) $sale["total_amount"], 2) ?>
                                </strong>
                            </td>

                            <td>
                                <?php
                                $saleTimestamp = strtotime($sale["sale_date"]);

                                echo $saleTimestamp !== false
                                    ? escape(date("M d, Y h:i A", $saleTimestamp))
                                    : "Invalid date";
                                ?>
                            </td>
                        </tr>

                    <?php endwhile; ?>

                <?php else: ?>

                    <tr>
                        <td colspan="6" class="text-center text-muted py-4">
                            No sales history available yet.
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
