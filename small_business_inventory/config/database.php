<?php

mysqli_report(MYSQLI_REPORT_OFF);

// Detect if online database settings are available
$host = getenv("DB_HOST") ?: "localhost";
$username = getenv("DB_USER") ?: "root";
$password = getenv("DB_PASSWORD") ?: "";
$database = getenv("DB_NAME") ?: "small_business_inventory";
$port = (int) (getenv("DB_PORT") ?: 3306);

// Create database connection
$conn = mysqli_init();

if (!$conn) {
    error_log("Unable to initialize database connection.");
    http_response_code(500);
    exit("Database connection error. Please try again later.");
}

// Enable SSL for TiDB Cloud
if (getenv("DB_HOST")) {
    $caPath = getenv("DB_SSL_CA");

    if ($caPath) {
        $conn->ssl_set(null, null, $caPath, null, null);
    }
}

// Connect to database
$connected = $conn->real_connect(
    $host,
    $username,
    $password,
    $database,
    $port,
    null,
    getenv("DB_HOST") ? MYSQLI_CLIENT_SSL : 0
);

// Check database connection
if (!$connected) {
    error_log("Database connection failed: " . $conn->connect_error);
    http_response_code(500);
    exit("Unable to connect to the database. Please try again later.");
}

// Set character encoding
if (!$conn->set_charset("utf8mb4")) {
    error_log("Database charset configuration failed: " . $conn->error);
    http_response_code(500);
    exit("Database configuration error. Please try again later.");
}

?>