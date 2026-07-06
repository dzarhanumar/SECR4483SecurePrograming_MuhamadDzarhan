<?php
// db_config.php - Centralised, least-privilege DB connection (PDO)
// Used by: search.php, auth.php
//
// Replaces the old mysqli connection that ran under a high-privilege
// root account (the thing that turned Flaw A's SQLi into a full
// database dump in the original search.php).

require_once __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;

Dotenv::createImmutable(__DIR__)->load();

$dsn  = $_ENV['DB_DSN']  ?? 'mysql:host=127.0.0.1;dbname=medic_vault_db;charset=utf8mb4';
$user = $_ENV['DB_USER'] ?? 'vault_app_user';
$pass = $_ENV['DB_PASS'] ?? '';

try {
    $pdo = new PDO($dsn, $user, $pass, [
        // Throw exceptions instead of silently failing or leaking
        // a raw fatal error with connection details in it.
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,

        // Real prepared statements sent to MySQL, not client-side
        // emulation - keeps the data/command separation genuine.
        PDO::ATTR_EMULATE_PREPARES => false,

        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $e) {
    // Fail closed, no stack trace or DSN/credentials leaked to the client.
    http_response_code(500);
    error_log('DB connection failed: ' . $e->getMessage());
    die('Service temporarily unavailable.');
}

// $pdo is now available to any file that does require_once 'db_config.php';
?>
