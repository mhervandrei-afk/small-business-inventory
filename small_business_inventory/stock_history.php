<?php
session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

require_once __DIR__ . "/config/database.php";

/**
 * @param mixed $value
 * @return string
 */
function escape($value): string {
    return htmlspecialchars((string)$value, ENT_QUOTES, "UTF-8");
}

// VERIFY CURRENT USER
$userId = (int)$_SESSION["user_id"];

$stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");

if (!$stmt) {
    error_log("User verification prepare failed: " . $conn->error);
    http_response_code(500);
    exit("Something went wrong. Please try again later.");
}

$stmt->bind_param("i", $userId);

if (!$stmt->execute()) {
    error_log("User verification failed: " . $stmt->error);
    $stmt->close();
    http_response_code(500);
    exit("Unable to verify user.");
}

$currentUser = $stmt->get_result()->fetch_assoc();
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

$userRole = strtolower(trim((string)$currentUser["role"]));

if (!in_array($userRole, ["administrator", "owner"], true)) {
    header("Location: dashboard.php");
    exit;
}

$_SESSION["user_role"] = $userRole;

// SEARCH AND FILTER VALIDATION
$searchInput = $_GET["search"] ?? "";
$typeInput = $_GET["type"] ?? "";

$search = is_string($searchInput)
    ? trim(substr($searchInput, 0, 100))
    : "";

$filter = is_string($typeInput)
    ? $typeInput
    : "";

$allowedTypes = ["Add Stock", "Remove Stock"];

if (!in_array($filter, $allowedTypes, true)) {
    $filter = "";
}

// BUILD STOCK HISTORY QUERY
$sql = "SELECT id, product_name, movement_type, quantity,
               previous_stock, new_stock, created_at
        FROM stock_movements
        WHERE 1=1";

$params = [];
$types = "";

if ($search !== "") {
    $sql .= " AND product_name LIKE ?";
    $params[] = "%" . $search . "%";
    $types .= "s";
}

if ($filter !== "") {
    $sql .= " AND movement_type = ?";
    $params[] = $filter;
    $types .= "s";
}

$sql .= " ORDER BY created_at DESC, id DESC";

$stmt = $conn->prepare($sql);

if (!$stmt) {
    error_log("Stock history prepare failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load stock movement history.");
}

if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}

if (!$stmt->execute()) {
    error_log("Stock history execution failed: " . $stmt->error);
    $stmt->close();

    http_response_code(500);
    exit("Unable to load stock movement history.");
}

$result = $stmt->get_result();

$movements = [];

while ($row = $result->fetch_assoc()) {
    $movements[] = $row;
}

$stmt->close();

// SUMMARY COUNTS
$summaryQuery = $conn->query("
    SELECT
        COUNT(*) AS total_movements,
        COALESCE(SUM(
            CASE
                WHEN movement_type = 'Add Stock' THEN quantity
                ELSE 0
            END
        ), 0) AS total_added,
        COALESCE(SUM(
            CASE
                WHEN movement_type = 'Remove Stock' THEN quantity
                ELSE 0
            END
        ), 0) AS total_removed
    FROM stock_movements
");

if (!$summaryQuery) {
    error_log("Stock summary query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load stock movement summary.");
}

$summary = $summaryQuery->fetch_assoc();
$summaryQuery->free();

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Stock Movement History</title>

    <link
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
        rel="stylesheet"
    >

    <style>
        body {
            background: #f3f5f8;
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
            height: 100%;
            box-shadow: 0 3px 12px rgba(0,0,0,0.05);
        }

        .summary-number {
            font-size: 28px;
            font-weight: bold;
            color: #172033;
        }

        .history-card {
            background: white;
            border: none;
            border-radius: 12px;
            padding: 22px;
            box-shadow: 0 3px 12px rgba(0,0,0,0.05);
        }

        .btn-orange {
            background: #ff9418;
            color: white;
            border: none;
        }

        .btn-orange:hover {
            background: #e9820b;
            color: white;
        }

        .table th {
            background: #172033;
            color: white;
            white-space: nowrap;
        }

        .table td {
            vertical-align: middle;
        }
    </style>
</head>

<body>

<nav class="navbar navbar-dark">
    <div class="container">

        <a class="navbar-brand" href="dashboard.php">
            Small Business Inventory
        </a>

        <div class="d-flex gap-2">

            <a href="products.php" class="btn btn-outline-light btn-sm">
                Products
            </a>

            <a href="dashboard.php" class="btn btn-outline-light btn-sm">
                Dashboard
            </a>

        </div>

    </div>
</nav>

<div class="container py-4">

    <div class="mb-4">
        <h2 class="page-title">Stock Movement History</h2>

        <p class="text-muted">
            Monitor all stock additions and removals.
        </p>
    </div>

    <!-- SUMMARY CARDS -->
    <div class="row g-3 mb-4">

        <div class="col-md-4">
            <div class="summary-card">

                <p class="text-muted mb-1">
                    Total Movements
                </p>

                <div class="summary-number">
                    <?= number_format((int)$summary["total_movements"]) ?>
                </div>

            </div>
        </div>

        <div class="col-md-4">
            <div class="summary-card">

                <p class="text-muted mb-1">
                    Total Stock Added
                </p>

                <div class="summary-number text-success">
                    <?= number_format((int)$summary["total_added"]) ?>
                </div>

            </div>
        </div>

        <div class="col-md-4">
            <div class="summary-card">

                <p class="text-muted mb-1">
                    Total Stock Removed
                </p>

                <div class="summary-number text-danger">
                    <?= number_format((int)$summary["total_removed"]) ?>
                </div>

            </div>
        </div>

    </div>

    <!-- HISTORY TABLE -->
    <div class="history-card">

        <div class="d-flex justify-content-between align-items-center mb-3">

            <h5 class="mb-0">
                Movement Records
            </h5>

            <a
                href="stock_history.php"
                class="btn btn-outline-secondary btn-sm"
            >
                Reset Filters
            </a>

        </div>

        <!-- SEARCH AND FILTER -->
        <form
            method="GET"
            action="stock_history.php"
            class="row g-2 mb-4"
        >

            <div class="col-md-6">

                <input
                    type="text"
                    name="search"
                    class="form-control"
                    placeholder="Search product name..."
                    value="<?= escape($search) ?>"
                    maxlength="100"
                >

            </div>

            <div class="col-md-4">

                <select name="type" class="form-select">

                    <option value="">
                        All Movements
                    </option>

                    <option
                        value="Add Stock"
                        <?= $filter === "Add Stock" ? "selected" : "" ?>
                    >
                        Add Stock
                    </option>

                    <option
                        value="Remove Stock"
                        <?= $filter === "Remove Stock" ? "selected" : "" ?>
                    >
                        Remove Stock
                    </option>

                </select>

            </div>

            <div class="col-md-2">

                <button
                    type="submit"
                    class="btn btn-orange w-100"
                >
                    Search
                </button>

            </div>

        </form>

        <!-- MOVEMENT RECORDS -->
        <div class="table-responsive">

            <table class="table table-bordered table-hover">

                <thead>

                    <tr>
                        <th>ID</th>
                        <th>Product</th>
                        <th>Movement Type</th>
                        <th>Quantity</th>
                        <th>Previous Stock</th>
                        <th>New Stock</th>
                        <th>Date and Time</th>
                    </tr>

                </thead>

                <tbody>

                    <?php if (count($movements) > 0): ?>

                        <?php foreach ($movements as $movement): ?>

                            <tr>

                                <td>
                                    <?= (int)$movement["id"] ?>
                                </td>

                                <td>
                                    <strong>
                                        <?= escape($movement["product_name"]) ?>
                                    </strong>
                                </td>

                                <td>

                                    <?php if ($movement["movement_type"] === "Add Stock"): ?>

                                        <span class="badge bg-success">
                                            Add Stock
                                        </span>

                                    <?php elseif ($movement["movement_type"] === "Remove Stock"): ?>

                                        <span class="badge bg-danger">
                                            Remove Stock
                                        </span>

                                    <?php else: ?>

                                        <span class="badge bg-secondary">
                                            <?= escape($movement["movement_type"]) ?>
                                        </span>

                                    <?php endif; ?>

                                </td>

                                <td>
                                    <?= number_format((int)$movement["quantity"]) ?>
                                </td>

                                <td>
                                    <?= number_format((int)$movement["previous_stock"]) ?>
                                </td>

                                <td>
                                    <strong>
                                        <?= number_format((int)$movement["new_stock"]) ?>
                                    </strong>
                                </td>

                                <td>

                                    <?php
                                    $timestamp = strtotime($movement["created_at"]);

                                    echo $timestamp !== false
                                        ? escape(date("M d, Y h:i A", $timestamp))
                                        : "Invalid date";
                                    ?>

                                </td>

                            </tr>

                        <?php endforeach; ?>

                    <?php else: ?>

                        <tr>
                            <td
                                colspan="7"
                                class="text-center text-muted py-4"
                            >
                                No stock movement records found.
                            </td>
                        </tr>

                    <?php endif; ?>

                </tbody>

            </table>

        </div>

        <p class="text-muted mb-0">
            Showing <?= count($movements) ?> movement record(s).
        </p>

    </div>

</div>

</body>
</html>