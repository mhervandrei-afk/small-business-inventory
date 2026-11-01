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

/**
 * @param string $message
 * @param string $type
 * @return void
 */
function setProductMessage(string $message, string $type = "success"): void {
    $_SESSION["product_message"] = $message;
    $_SESSION["product_message_type"] = $type;
}

// Verify current user and role
$userId = (int)$_SESSION["user_id"];

$stmt = $conn->prepare("SELECT role FROM users WHERE id = ?");

if (!$stmt) {
    error_log("User verification failed: " . $conn->error);
    http_response_code(500);
    exit("Something went wrong. Please try again later.");
}

$stmt->bind_param("i", $userId);
$stmt->execute();

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
if (empty($_SESSION["csrf_token"])) {
    $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
}

// Create products table if it does not exist
$createTable = "CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product_name VARCHAR(150) NOT NULL,
    category VARCHAR(100) NOT NULL DEFAULT 'Uncategorized',
    price DECIMAL(10,2) NOT NULL,
    stock INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";

if (!$conn->query($createTable)) {
    error_log("Products table creation failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load product management.");
}

$message = "";
$messageType = "success";

// Validate CSRF token for all POST requests
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

// ADD PRODUCT
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["add_product"])) {

    $productName = trim($_POST["product_name"] ?? "");
    $category = trim($_POST["category"] ?? "");
    $price = $_POST["price"] ?? "";
    $stock = $_POST["stock"] ?? "";

    $validPrice = is_scalar($price) &&
        is_numeric($price) &&
        is_finite((float)$price) &&
        (float)$price >= 0 &&
        (float)$price <= 99999999.99;

    $validStock = is_scalar($stock) &&
        preg_match('/^\d+$/', (string)$stock) &&
        (float)$stock <= 2147483647;

    if (
        $productName === "" ||
        strlen($productName) > 150 ||
        $category === "" ||
        strlen($category) > 100 ||
        !$validPrice ||
        !$validStock
    ) {
        setProductMessage("Please enter valid product information.", "danger");

    } else {
        $priceValue = (float)$price;
        $stockValue = (int)$stock;

        $stmt = $conn->prepare(
            "INSERT INTO products (product_name, category, price, stock)
             VALUES (?, ?, ?, ?)"
        );

        if (!$stmt) {
            error_log("Add product prepare failed: " . $conn->error);
            setProductMessage("Unable to add product.", "danger");
        } else {
            $stmt->bind_param("ssdi", $productName, $category, $priceValue, $stockValue);

            if ($stmt->execute()) {
                setProductMessage("Product successfully added!");
            } else {
                error_log("Add product failed: " . $stmt->error);
                setProductMessage("Unable to add product.", "danger");
            }

            $stmt->close();
        }
    }

    header("Location: products.php");
    exit;
}

// UPDATE PRODUCT
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["update_product"])) {

    $id = (int)($_POST["id"] ?? 0);
    $productName = trim($_POST["product_name"] ?? "");
    $category = trim($_POST["category"] ?? "");
    $price = $_POST["price"] ?? "";
    $stock = $_POST["stock"] ?? "";

    $validPrice = is_scalar($price) &&
        is_numeric($price) &&
        is_finite((float)$price) &&
        (float)$price >= 0 &&
        (float)$price <= 99999999.99;

    $validStock = is_scalar($stock) &&
        preg_match('/^\d+$/', (string)$stock) &&
        (float)$stock <= 2147483647;

    if (
        $id <= 0 ||
        $productName === "" ||
        strlen($productName) > 150 ||
        $category === "" ||
        strlen($category) > 100 ||
        !$validPrice ||
        !$validStock
    ) {
        setProductMessage("Please enter valid product information.", "danger");

    } else {
        $priceValue = (float)$price;
        $stockValue = (int)$stock;

        $stmt = $conn->prepare(
            "UPDATE products
             SET product_name = ?, category = ?, price = ?, stock = ?
             WHERE id = ?"
        );

        if (!$stmt) {
            error_log("Update product prepare failed: " . $conn->error);
            setProductMessage("Unable to update product.", "danger");
        } else {
            $stmt->bind_param(
                "ssdii",
                $productName,
                $category,
                $priceValue,
                $stockValue,
                $id
            );

            if ($stmt->execute()) {
                if ($stmt->affected_rows >= 0) {
                    setProductMessage("Product successfully updated!");
                } else {
                    setProductMessage("Unable to update product.", "danger");
                }
            } else {
                error_log("Update product failed: " . $stmt->error);
                setProductMessage("Unable to update product.", "danger");
            }

            $stmt->close();
        }
    }

    header("Location: products.php");
    exit;
}

// DELETE PRODUCT
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["delete_product"])) {

    $id = (int)($_POST["id"] ?? 0);

    if ($id <= 0) {
        setProductMessage("Invalid product selected.", "danger");
    } else {
        // Check whether product has sales history
        $stmt = $conn->prepare(
            "SELECT COUNT(*) AS total FROM sales WHERE product_id = ?"
        );

        if (!$stmt) {
            error_log("Sales history check failed: " . $conn->error);
            setProductMessage("Unable to delete product.", "danger");
        } else {
            $stmt->bind_param("i", $id);
            $stmt->execute();

            $salesCount = (int)$stmt->get_result()->fetch_assoc()["total"];
            $stmt->close();

            if ($salesCount > 0) {
                setProductMessage(
                    "This product has sales history and cannot be deleted. You can keep it for record purposes or set its stock to zero.",
                    "danger"
                );
            } else {
                $stmt = $conn->prepare("DELETE FROM products WHERE id = ?");

                if (!$stmt) {
                    error_log("Delete product prepare failed: " . $conn->error);
                    setProductMessage("Unable to delete product.", "danger");
                } else {
                    $stmt->bind_param("i", $id);

                    if ($stmt->execute() && $stmt->affected_rows > 0) {
                        setProductMessage("Product successfully deleted!");
                    } else {
                        setProductMessage("Product not found or could not be deleted.", "danger");
                    }

                    $stmt->close();
                }
            }
        }
    }

    header("Location: products.php");
    exit;
}

// GET MESSAGE
if (isset($_SESSION["product_message"])) {
    $message = $_SESSION["product_message"];
    $messageType = $_SESSION["product_message_type"] ?? "success";

    unset($_SESSION["product_message"]);
    unset($_SESSION["product_message_type"]);
}

// GET PRODUCT FOR EDITING
$editProduct = null;

if (isset($_GET["edit"])) {
    $editId = filter_var($_GET["edit"], FILTER_VALIDATE_INT);

    if ($editId !== false && $editId > 0) {
        $stmt = $conn->prepare("SELECT * FROM products WHERE id = ?");

        if (!$stmt) {
            error_log("Edit product query failed: " . $conn->error);
            http_response_code(500);
            exit("Unable to load product.");
        }

        $stmt->bind_param("i", $editId);
        $stmt->execute();

        $editProduct = $stmt->get_result()->fetch_assoc();
        $stmt->close();
    }
}

// SEARCH, CATEGORY FILTER, AND SORTING
$searchTerm = trim($_GET["search"] ?? "");
$selectedCategory = trim($_GET["category"] ?? "");
$sort = $_GET["sort"] ?? "newest";

$sortOptions = [
    "newest" => "id DESC",
    "name_asc" => "product_name ASC",
    "price_asc" => "price ASC",
    "price_desc" => "price DESC",
    "stock_asc" => "stock ASC",
    "stock_desc" => "stock DESC"
];

$orderBy = $sortOptions[$sort] ?? "id DESC";

// GET AVAILABLE CATEGORIES
$categoryResult = $conn->query(
    "SELECT DISTINCT category FROM products ORDER BY category ASC"
);

if (!$categoryResult) {
    error_log("Category query failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load product categories.");
}

// BUILD PRODUCT QUERY
$sql = "SELECT * FROM products WHERE 1=1";

$params = [];
$types = "";

if ($searchTerm !== "") {
    $sql .= " AND product_name LIKE ?";
    $params[] = "%" . $searchTerm . "%";
    $types .= "s";
}

if ($selectedCategory !== "") {
    $sql .= " AND category = ?";
    $params[] = $selectedCategory;
    $types .= "s";
}

$sql .= " ORDER BY " . $orderBy;

$stmt = $conn->prepare($sql);

if (!$stmt) {
    error_log("Product list prepare failed: " . $conn->error);
    http_response_code(500);
    exit("Unable to load products.");
}

if (!empty($params)) {
    $stmt->bind_param($types, ...$params);
}

$stmt->execute();
$products = $stmt->get_result();

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Products | Small Business Inventory</title>

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
            font-weight: bold;
        }

        .page-title {
            color: #172033;
            font-weight: bold;
        }

        .main-card {
            border: none;
            border-radius: 12px;
        }

        .btn-orange {
            background: #ff9418;
            color: white;
            border: none;
        }

        .btn-orange:hover {
            background: #e98208;
            color: white;
        }

        .table thead th {
            background: #172033;
            color: white;
        }

        .form-control,
        .form-select {
            border-radius: 7px;
        }
    </style>
</head>

<body>

<nav class="navbar navbar-dark">
    <div class="container">

        <a class="navbar-brand" href="dashboard.php">
            📦 Small Business Inventory
        </a>

        <div>
            <a href="dashboard.php" class="btn btn-outline-light btn-sm">
                Dashboard
            </a>

            <a href="logout.php" class="btn btn-outline-light btn-sm">
                Logout
            </a>
        </div>

    </div>
</nav>

<div class="container py-5">

    <div class="d-flex justify-content-between align-items-center flex-wrap mb-4">
        <div>
            <h2 class="page-title">Product Management</h2>
            <p class="text-muted mb-0">
                Add and manage your business products.
            </p>
        </div>
    </div>

    <?php if ($message !== ""): ?>
        <div class="alert alert-<?= escape($messageType) ?> alert-dismissible fade show">
            <?= escape($message) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <!-- ADD / EDIT PRODUCT FORM -->
    <div class="card main-card shadow-sm mb-4">

        <div class="card-body p-4">

            <h5 class="fw-bold mb-3">
                <?= $editProduct ? "Edit Product" : "Add New Product" ?>
            </h5>

            <form method="POST" action="products.php">

                <input type="hidden"
                    name="csrf_token"
                    value="<?= escape($_SESSION["csrf_token"]) ?>">

                <?php if ($editProduct): ?>
                    <input type="hidden" name="id" value="<?= (int)$editProduct["id"] ?>">
                <?php endif; ?>

                <div class="row g-3">

                    <div class="col-md-6">
                        <label class="form-label">Product Name</label>

                        <input
                            type="text"
                            name="product_name"
                            class="form-control"
                            placeholder="Enter product name"
                            maxlength="150"
                            value="<?= escape($editProduct["product_name"] ?? "") ?>"
                            required
                        >
                    </div>

                    <div class="col-md-6">
                        <label class="form-label">Category</label>

                        <input
                            type="text"
                            name="category"
                            class="form-control"
                            placeholder="Example: Food, Drinks, Supplies"
                            maxlength="100"
                            value="<?= escape($editProduct["category"] ?? "") ?>"
                            required
                        >
                    </div>

                    <div class="col-md-6">
                        <label class="form-label">Price (₱)</label>

                        <input
                            type="number"
                            name="price"
                            class="form-control"
                            placeholder="0.00"
                            min="0"
                            max="99999999.99"
                            step="0.01"
                            value="<?= escape($editProduct["price"] ?? "") ?>"
                            required
                        >
                    </div>

                    <div class="col-md-6">
                        <label class="form-label">Stock Quantity</label>

                        <input
                            type="number"
                            name="stock"
                            class="form-control"
                            placeholder="Enter stock quantity"
                            min="0"
                            step="1"
                            value="<?= escape($editProduct["stock"] ?? "") ?>"
                            required
                        >
                    </div>

                    <div class="col-12">

                        <?php if ($editProduct): ?>

                            <button type="submit" name="update_product" class="btn btn-orange">
                                Update Product
                            </button>

                            <a href="products.php" class="btn btn-secondary">
                                Cancel
                            </a>

                        <?php else: ?>

                            <button type="submit" name="add_product" class="btn btn-orange">
                                + Add Product
                            </button>

                        <?php endif; ?>

                    </div>

                </div>

            </form>

        </div>
    </div>

    <!-- SEARCH, FILTER, AND SORTING -->
    <div class="card main-card shadow-sm mb-4">

        <div class="card-body p-4">

            <h5 class="fw-bold mb-3">Search, Filter and Sort Products</h5>

            <form method="GET" action="products.php">

                <div class="row g-2">

                    <div class="col-md-4">
                        <input
                            type="text"
                            name="search"
                            class="form-control"
                            placeholder="Search product name..."
                            value="<?= escape($searchTerm) ?>"
                        >
                    </div>

                    <div class="col-md-3">
                        <select name="category" class="form-select">
                            <option value="">All Categories</option>

                            <?php while ($cat = $categoryResult->fetch_assoc()): ?>
                                <option
                                    value="<?= escape($cat["category"]) ?>"
                                    <?= $selectedCategory === $cat["category"] ? "selected" : "" ?>
                                >
                                    <?= escape($cat["category"]) ?>
                                </option>
                            <?php endwhile; ?>

                        </select>
                    </div>

                    <div class="col-md-3">
                        <select name="sort" class="form-select">

                            <option value="newest" <?= $sort === "newest" ? "selected" : "" ?>>
                                Newest First
                            </option>

                            <option value="name_asc" <?= $sort === "name_asc" ? "selected" : "" ?>>
                                Name (A-Z)
                            </option>

                            <option value="price_asc" <?= $sort === "price_asc" ? "selected" : "" ?>>
                                Price (Lowest First)
                            </option>

                            <option value="price_desc" <?= $sort === "price_desc" ? "selected" : "" ?>>
                                Price (Highest First)
                            </option>

                            <option value="stock_asc" <?= $sort === "stock_asc" ? "selected" : "" ?>>
                                Stock (Lowest First)
                            </option>

                            <option value="stock_desc" <?= $sort === "stock_desc" ? "selected" : "" ?>>
                                Stock (Highest First)
                            </option>

                        </select>
                    </div>

                    <div class="col-md-2 d-flex gap-2">
                        <button type="submit" class="btn btn-orange flex-fill">
                            Search
                        </button>

                        <a href="products.php" class="btn btn-secondary flex-fill">
                            Clear
                        </a>
                    </div>

                </div>

            </form>

        </div>
    </div>

    <!-- PRODUCT TABLE -->
    <div class="card main-card shadow-sm">

        <div class="card-body p-4">

            <h5 class="fw-bold mb-3">Product List</h5>

            <div class="table-responsive">

                <table class="table table-bordered table-hover align-middle">

                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Product Name</th>
                            <th>Category</th>
                            <th>Price</th>
                            <th>Stock</th>
                            <th width="180">Actions</th>
                        </tr>
                    </thead>

                    <tbody>

                    <?php if ($products->num_rows > 0): ?>

                        <?php while ($product = $products->fetch_assoc()): ?>

                            <tr>

                                <td><?= (int)$product["id"] ?></td>

                                <td><?= escape($product["product_name"]) ?></td>

                                <td><?= escape($product["category"]) ?></td>

                                <td>₱<?= number_format((float)$product["price"], 2) ?></td>

                                <td>

                                    <?php if ((int)$product["stock"] <= 5): ?>

                                        <span class="badge bg-danger">
                                            <?= (int)$product["stock"] ?> - Low Stock
                                        </span>

                                    <?php else: ?>

                                        <span class="badge bg-success">
                                            <?= (int)$product["stock"] ?>
                                        </span>

                                    <?php endif; ?>

                                </td>

                                <td>

                                    <a
                                        href="products.php?edit=<?= (int)$product["id"] ?>"
                                        class="btn btn-warning btn-sm"
                                    >
                                        Edit
                                    </a>

                                    <a
                                        href="stock_adjustment.php?id=<?= (int)$product["id"] ?>"
                                        class="btn btn-info btn-sm text-white"
                                    >
                                        Adjust Stock
                                    </a>

                                    <form
                                        method="POST"
                                        action="products.php"
                                        class="d-inline"
                                        onsubmit="return confirm('Are you sure you want to delete this product?');"
                                    >

                                        <input type="hidden"
                                            name="csrf_token"
                                            value="<?= escape($_SESSION["csrf_token"]) ?>">

                                        <input
                                            type="hidden"
                                            name="id"
                                            value="<?= (int)$product["id"] ?>"
                                        >

                                        <button
                                            type="submit"
                                            name="delete_product"
                                            class="btn btn-danger btn-sm"
                                        >
                                            Delete
                                        </button>

                                    </form>

                                </td>

                            </tr>

                        <?php endwhile; ?>

                    <?php else: ?>

                        <tr>
                            <td colspan="6" class="text-center text-muted py-4">
                                No products found. Try another search or category.
                            </td>
                        </tr>

                    <?php endif; ?>

                    </tbody>

                </table>

            </div>

            <p class="text-muted mb-0">
                Showing <?= (int)$products->num_rows ?> product(s).
            </p>

        </div>
    </div>

    <div class="text-center mt-4">
        <a href="dashboard.php" class="text-decoration-none">
            ← Back to Dashboard
        </a>
    </div>

</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>