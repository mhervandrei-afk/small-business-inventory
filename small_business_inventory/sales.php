<?php
session_start();

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

require_once __DIR__ . "/config/database.php";

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

// Generate CSRF token
if (
    !isset($_SESSION["csrf_token"]) ||
    !is_string($_SESSION["csrf_token"]) ||
    $_SESSION["csrf_token"] === ""
) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

$message = "";
$messageType = "success";

// Validate CSRF token
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $submittedToken = $_POST["csrf_token"] ?? "";

    if (
        !is_string($submittedToken) ||
        !hash_equals($_SESSION["csrf_token"], $submittedToken)
    ) {
        http_response_code(403);
        exit("Invalid or expired form token. Please refresh the page and try again.");
    }
}

// Record a sale
if (
    $_SERVER["REQUEST_METHOD"] === "POST" &&
    isset($_POST["record_sale"])
) {
    $rawProductId = $_POST["product_id"] ?? "";
    $rawQuantity = $_POST["quantity"] ?? "";

    $productId = filter_var($rawProductId, FILTER_VALIDATE_INT);
    $quantity = filter_var($rawQuantity, FILTER_VALIDATE_INT);

    if (
        $productId === false ||
        $productId <= 0 ||
        $quantity === false ||
        $quantity <= 0
    ) {
        $message = "Please select a product and enter a valid quantity.";
        $messageType = "danger";
    } else {
        try {
            // Start database transaction
            if (!$conn->begin_transaction()) {
                throw new Exception("Unable to start transaction.");
            }

            // Lock product row while processing sale
            $stmt = $conn->prepare(
                "SELECT product_name, price, stock
                 FROM products
                 WHERE id = ?
                 FOR UPDATE"
            );

            if (!$stmt) {
                throw new Exception("Product query preparation failed.");
            }

            $stmt->bind_param("i", $productId);

            if (!$stmt->execute()) {
                throw new Exception("Product query failed.");
            }

            $product = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            if (!$product) {
                throw new Exception("Product not found.");
            }

            $availableStock = (int) $product["stock"];

            if ($availableStock <= 0) {
                throw new Exception("This product is out of stock.");
            }

            if ($quantity > $availableStock) {
                throw new Exception("Not enough stock available.");
            }

            $productName = (string) $product["product_name"];
            $unitPrice = (float) $product["price"];
            $totalAmount = round($unitPrice * $quantity, 2);

            if ($unitPrice < 0 || $totalAmount < 0) {
                throw new Exception("Invalid product price.");
            }

            // Deduct stock
            $stmt = $conn->prepare(
                "UPDATE products
                 SET stock = stock - ?
                 WHERE id = ? AND stock >= ?"
            );

            if (!$stmt) {
                throw new Exception("Stock update preparation failed.");
            }

            $stmt->bind_param(
                "iii",
                $quantity,
                $productId,
                $quantity
            );

            if (!$stmt->execute()) {
                throw new Exception("Unable to update product stock.");
            }

            if ($stmt->affected_rows !== 1) {
                $stmt->close();
                throw new Exception("Stock changed or is insufficient. Please try again.");
            }

            $stmt->close();

            // Insert sale using the existing sales table structure
            $stmt = $conn->prepare(
                "INSERT INTO sales
                 (user_id, product_id, product_name, quantity, unit_price, total_amount)
                 VALUES (?, ?, ?, ?, ?, ?)"
            );

            if (!$stmt) {
                throw new Exception("Sale preparation failed.");
            }

            $stmt->bind_param(
                "iisidd",
                $userId,
                $productId,
                $productName,
                $quantity,
                $unitPrice,
                $totalAmount
            );

            if (!$stmt->execute()) {
                throw new Exception("Unable to save sale.");
            }

            $stmt->close();

            // Commit both stock deduction and sale record
            if (!$conn->commit()) {
                throw new Exception("Unable to complete sale.");
            }

            $message = "Sale recorded successfully! Total: ₱" .
                       number_format($totalAmount, 2);

            $messageType = "success";

        } catch (Throwable $e) {
            $conn->rollback();

            error_log("Sales processing error: " . $e->getMessage());

            // Show safe business messages only
            $allowedMessages = [
                "Product not found.",
                "This product is out of stock.",
                "Not enough stock available.",
                "Invalid product price.",
                "Stock changed or is insufficient. Please try again."
            ];

            if (in_array($e->getMessage(), $allowedMessages, true)) {
                $message = $e->getMessage();
            } else {
                $message = "Unable to record sale. Please try again.";
            }

            $messageType = "danger";
        }
    }
}

// Get available products
$products = $conn->query(
    "SELECT id, product_name, price, stock
     FROM products
     WHERE stock > 0
     ORDER BY product_name ASC"
);

if (!$products) {
    error_log("Products query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load products. Please try again later.");
}

// Get sales history
$sales = $conn->query(
    "SELECT id, product_name, quantity, unit_price,
            total_amount, sale_date
     FROM sales
     ORDER BY sale_date DESC, id DESC"
);

if (!$sales) {
    error_log("Sales history query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load sales history. Please try again later.");
}

// Get sales summary
$summaryResult = $conn->query(
    "SELECT
        COUNT(*) AS total_transactions,
        COALESCE(SUM(quantity), 0) AS items_sold,
        COALESCE(SUM(total_amount), 0) AS total_sales
     FROM sales"
);

if (!$summaryResult) {
    error_log("Sales summary query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load sales summary. Please try again later.");
}

$summary = $summaryResult->fetch_assoc();
$summaryResult->free();

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Sales Management | Small Business System</title>

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

        .summary-card h2 {
            color: #ff9418;
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

    <div class="mb-4">
        <h2 class="page-title">Sales Management</h2>
        <p class="text-muted">
            Record sales and monitor your business transactions.
        </p>
    </div>

    <?php if ($message !== ""): ?>
        <div class="alert alert-<?= escape($messageType) ?>">
            <?= escape($message) ?>
        </div>
    <?php endif; ?>

    <!-- Sales Summary -->
    <div class="row g-3 mb-4">

        <div class="col-md-4">
            <div class="summary-card">
                <p class="text-muted mb-1">Total Sales</p>
                <h2>₱<?= number_format((float) $summary["total_sales"], 2) ?></h2>
            </div>
        </div>

        <div class="col-md-4">
            <div class="summary-card">
                <p class="text-muted mb-1">Total Transactions</p>
                <h2><?= (int) $summary["total_transactions"] ?></h2>
            </div>
        </div>

        <div class="col-md-4">
            <div class="summary-card">
                <p class="text-muted mb-1">Items Sold</p>
                <h2><?= (int) $summary["items_sold"] ?></h2>
            </div>
        </div>

    </div>

    <!-- Record Sale Form -->
    <div class="content-card mb-4">

        <h5 class="mb-3">Record New Sale</h5>

        <form method="POST" action="sales.php">

            <input
                type="hidden"
                name="csrf_token"
                value="<?= escape($_SESSION["csrf_token"]) ?>"
            >

            <div class="row g-3">

                <div class="col-md-5">
                    <label class="form-label">Select Product</label>

                    <select name="product_id" class="form-select" required>
                        <option value="">Choose a product</option>

                        <?php while ($product = $products->fetch_assoc()): ?>

                            <option value="<?= (int) $product["id"] ?>">
                                <?= escape($product["product_name"]) ?>
                                - ₱<?= number_format((float) $product["price"], 2) ?>
                                (Stock: <?= (int) $product["stock"] ?>)
                            </option>

                        <?php endwhile; ?>

                    </select>
                </div>

                <div class="col-md-3">
                    <label class="form-label">Quantity Sold</label>

                    <input
                        type="number"
                        name="quantity"
                        class="form-control"
                        min="1"
                        step="1"
                        required
                    >
                </div>

                <div class="col-md-4 d-flex align-items-end">
                    <button
                        type="submit"
                        name="record_sale"
                        value="1"
                        class="btn btn-orange w-100"
                    >
                        Record Sale
                    </button>
                </div>

            </div>

        </form>

    </div>

    <!-- Sales History -->
    <div class="content-card">

        <h5 class="mb-3">Sales History</h5>

        <div class="table-responsive">

            <table class="table table-hover align-middle">

                <thead class="table-dark">
                    <tr>
                        <th>Sale ID</th>
                        <th>Product</th>
                        <th>Quantity</th>
                        <th>Unit Price</th>
                        <th>Total Amount</th>
                        <th>Date</th>
                    </tr>
                </thead>

                <tbody>

                    <?php if ($sales->num_rows > 0): ?>

                        <?php while ($sale = $sales->fetch_assoc()): ?>

                            <tr>
                                <td><?= (int) $sale["id"] ?></td>

                                <td>
                                    <?= escape($sale["product_name"]) ?>
                                </td>

                                <td>
                                    <?= (int) $sale["quantity"] ?>
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
                                    $timestamp = strtotime($sale["sale_date"]);

                                    echo $timestamp !== false
                                        ? escape(date("M d, Y h:i A", $timestamp))
                                        : "Invalid date";
                                    ?>
                                </td>
                            </tr>

                        <?php endwhile; ?>

                    <?php else: ?>

                        <tr>
                            <td colspan="6" class="text-center text-muted py-4">
                                No sales recorded yet.
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