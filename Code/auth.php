<?php
// auth.php - Secure Refactor
// Fixes: Flaw D (byte-based bound check) + Flaw E (MD5, no salt, hardcoded hash)
require_once 'db_config.php'; // returns a PDO instance, least-privilege DB user

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $inputKey = $_POST['auth_key'] ?? '';

    // Semantic character-length boundary, not raw byte count.
    // mb_strlen() decodes the text first so multi-byte characters
    // (emoji, CJK, etc.) are counted as one character each, closing
    // the bypass that let oversized multi-byte payloads slip past strlen().
    if (mb_strlen($inputKey, 'UTF-8') > 128) {
        http_response_code(400);
        die('Invalid credential length.');
    }

    // Hash pulled from DB per-username, never hardcoded, always salted
    // by Argon2id itself.
    $stmt = $pdo->prepare('SELECT auth_key_hash FROM staff_credentials WHERE username = :u');
    $stmt->execute([':u' => $_POST['username'] ?? '']);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    // password_verify() is constant-time and Argon2id is memory-hard,
    // so offline cracking of a leaked hash is no longer cheap or fast.
    if ($row && password_verify($inputKey, $row['auth_key_hash'])) {
        echo 'Access Granted.';
    } else {
        http_response_code(401);
        echo 'Access Denied.';
    }
}

// One-off migration helper for seeding new hashes (run once, then remove):
// $hash = password_hash($plainKey, PASSWORD_ARGON2ID,
//     ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 2]);
?>
