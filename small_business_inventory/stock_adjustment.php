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

// Verify user role
$userId = (int)$_SESSION["user_id"];

$stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");

if (!$stmt) {
    error_log("User verification failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to verify user.");
}

$stmt->bind_param("i", $userId);

if (!$stmt->execute()) {
    error_log("User verification execution failed: " . $stmt->error);
    $stmt->close();
    http_response_code(500);
    exit("Unable to verify user.");
}

$currentUser = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$currentUser) {
    $_SESSION = [];
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

// Generate CSRF token
if (
    !isset($_SESSION["csrf_token"]) ||
    !is_string($_SESSION["csrf_token"])
) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

$productId = filter_var(
    $_GET["id"] ?? 0,
    FILTER_VALIDATE_INT
);

$productId = ($productId !== false && $productId > 0)
    ? $productId
    : 0;

$message = "";
$messageType = "danger";

// PROCESS STOCK ADJUSTMENT
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    // Validate CSRF token
    $submittedToken = $_POST["csrf_token"] ?? "";

    if (
        !is_string($submittedToken) ||
        !hash_equals($_SESSION["csrf_token"], $submittedToken)
    ) {
        http_response_code(403);
        exit("Invalid or expired form token. Please refresh the page and try again.");
    }

    $postedProductId = filter_var(
        $_POST["product_id"] ?? 0,
        FILTER_VALIDATE_INT
    );

    $productId = (
        $postedProductId !== false &&
        $postedProductId > 0
    ) ? $postedProductId : 0;

    $movementType = $_POST["movement_type"] ?? "";
    $quantityInput = $_POST["quantity"] ?? "";

    // Validate quantity before converting it to integer
    $validQuantity = is_string($quantityInput) &&
        preg_match('/^[1-9][0-9]*$/', $quantityInput) &&
        strlen($quantityInput) <= 10 &&
        (float)$quantityInput <= 2147483647;

    if ($productId <= 0 || !$validQuantity) {
        $message = "Please enter a valid product and quantity.";

    } elseif (
        !is_string($movementType) ||
        !in_array($movementType, ["Add Stock", "Remove Stock"], true)
    ) {
        $message = "Invalid stock adjustment type.";

    } else {
        $quantity = (int)$quantityInput;

        try {
            if (!$conn->begin_transaction()) {
                throw new Exception("Unable to start stock adjustment.");
            }

            // Lock product record while adjusting stock
            $stmt = $conn->prepare(
                "SELECT id, product_name, stock
                 FROM products
                 WHERE id = ?
                 FOR UPDATE"
            );

            if (!$stmt) {
                throw new Exception("Unable to prepare product query.");
            }

            $stmt->bind_param("i", $productId);

            if (!$stmt->execute()) {
                throw new Exception("Unable to retrieve product.");
            }

            $product = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            if (!$product) {
                throw new Exception("Product not found.");
            }

            $productName = (string)$product["product_name"];
            $previousStock = (int)$product["stock"];

            if ($movementType === "Add Stock") {

                if ($quantity > 2147483647 - $previousStock) {
                    throw new Exception("The resulting stock quantity is too large.");
                }

                $newStock = $previousStock + $quantity;

            } else {

                if ($quantity > $previousStock) {
                    throw new Exception("Not enough stock to remove.");
                }

                $newStock = $previousStock - $quantity;
            }

            // Update product stock
            $update = $conn->prepare(
                "UPDATE products SET stock = ? WHERE id = ?"
            );

            if (!$update) {
                throw new Exception("Unable to prepare stock update.");
            }

            $update->bind_param("ii", $newStock, $productId);

            if (!$update->execute()) {
                $error = $update->error;
                $update->close();
                throw new Exception("Unable to update stock.");
            }

            $update->close();

            // Save movement history
            $history = $conn->prepare(
                "INSERT INTO stock_movements
                (product_id, product_name, movement_type, quantity,
                 previous_stock, new_stock)
                VALUES (?, ?, ?, ?, ?, ?)"
            );

            if (!$history) {
                throw new Exception("Unable to prepare stock history.");
            }

            $history->bind_param(
                "issiii",
                $productId,
                $productName,
                $movementType,
                $quantity,
                $previousStock,
                $newStock
            );

            if (!$history->execute()) {
                $history->close();
                throw new Exception("Unable to save stock movement history.");
            }

            $history->close();

            if (!$conn->commit()) {
                throw new Exception("Unable to complete stock adjustment.");
            }

            $_SESSION["product_message"] =
                "Stock adjustment and movement history saved successfully!";

            $_SESSION["product_message_type"] = "success";

            header("Location: products.php");
            exit;

        } catch (Throwable $e) {

            $conn->rollback();

            error_log("Stock adjustment error: " . $e->getMessage());

            // Show safe validation messages only
            $safeMessages = [
                "Product not found.",
                "Not enough stock to remove.",
                "The resulting stock quantity is too large.",
                "Unable to start stock adjustment."
            ];

            if (in_array($e->getMessage(), $safeMessages, true)) {
                $message = $e->getMessage();
            } else {
                $message = "Stock adjustment failed. Please try again.";
            }
        }
    }
}

// GET SELECTED PRODUCT
if ($productId <= 0) {
    $_SESSION["product_message"] = "Please select a valid product.";
    $_SESSION["product_message_type"] = "danger";
    header("Location: products.php");
    exit;
}

$stmt = $conn->prepare(
    "SELECT id, product_name, category, price, stock
     FROM products
     WHERE id = ?"
);

if (!$stmt) {
    error_log("Product lookup failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load product.");
}

$stmt->bind_param("i", $productId);

if (!$stmt->execute()) {
    error_log("Product lookup execution failed: " . $stmt->error);
    $stmt->close();
    http_response_code(500);
    exit("Unable to load product.");
}

$product = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$product) {
    $_SESSION["product_message"] = "Product not found.";
    $_SESSION["product_message_type"] = "danger";
    header("Location: products.php");
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Stock Adjustment | Small Business Inventory</title>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet">

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

        .adjustment-card {
            max-width: 600px;
            margin: 50px auto;
            padding: 30px;
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
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
    </style>
</head>

<body>

<nav class="navbar navbar-dark">
    <div class="container">

        <a class="navbar-brand" href="dashboard.php">
            Small Business Inventory
        </a>

        <a href="products.php" class="btn btn-outline-light btn-sm">
            Back to Products
        </a>

    </div>
</nav>

<div class="container">

    <div class="adjustment-card">

        <h3 class="mb-4">Stock Adjustment</h3>

        <?php if ($message !== ""): ?>
            <div class="alert alert-<?= escape($messageType) ?>">
                <?= escape($message) ?>
            </div>
        <?php endif; ?>

        <div class="mb-4">

            <h5><?= escape($product["product_name"]) ?></h5>

            <p class="text-muted mb-1">
                Category: <?= escape($product["category"]) ?>
            </p>

            <p class="mb-0">
                Current Stock:
                <strong><?= (int)$product["stock"] ?></strong>
            </p>

        </div>

        <hr>

        <form method="POST" action="stock_adjustment.php?id=<?= (int)$product["id"] ?>">

            <input
                type="hidden"
                name="csrf_token"
                value="<?= escape($_SESSION["csrf_token"]) ?>"
            >

            <input
                type="hidden"
                name="product_id"
                value="<?= (int)$product["id"] ?>"
            >

            <div class="mb-3">

                <label class="form-label">Adjustment Type</label>

                <select name="movement_type" class="form-select" required>
                    <option value="Add Stock">Add Stock</option>
                    <option value="Remove Stock">Remove Stock</option>
                </select>

            </div>

            <div class="mb-4">

                <label class="form-label">Quantity</label>

                <input
                    type="number"
                    name="quantity"
                    class="form-control"
                    min="1"
                    max="2147483647"
                    step="1"
                    required
                    placeholder="Enter quantity"
                >

            </div>

            <button type="submit" class="btn btn-orange w-100">
                Save Adjustment
            </button>

            <a href="products.php" class="btn btn-secondary w-100 mt-2">
                Cancel
            </a>

        </form>

    </div>

</div>

</body>
</html>