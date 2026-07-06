<?php
// crypto_vault.php - Secure Refactor (AES-256-GCM)
// Fixes: Flaw F (AES-128-ECB, no integrity check) + Flaw G (hardcoded key)
require_once __DIR__ . '/vendor/autoload.php';

use Dotenv\Dotenv;

Dotenv::createImmutable(__DIR__)->load();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $medical_payload = $_POST['payload'] ?? '';

    // Secret now lives outside the codebase entirely (.env, git-ignored).
    $secret_key = base64_decode($_ENV['VAULT_KEY_B64']); // 32 raw bytes for AES-256

    $iv  = random_bytes(12); // fresh, unpredictable nonce every call
    $tag = '';

    $ciphertext = openssl_encrypt(
        $medical_payload, 'aes-256-gcm', $secret_key,
        OPENSSL_RAW_DATA, $iv, $tag, '', 16
    );

    if ($ciphertext === false) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Encryption failed.']);
        exit;
    }

    // Pack IV(12) + Tag(16) + Ciphertext, then base64 for transport.
    $packed = base64_encode($iv . $tag . $ciphertext);

    echo json_encode(['status' => 'vaulted', 'data' => $packed]);
}

function vaultDecrypt(string $packedB64, string $key): string
{
    $raw        = base64_decode($packedB64);
    $iv         = substr($raw, 0, 12);
    $tag        = substr($raw, 12, 16);
    $ciphertext = substr($raw, 28);

    $plaintext = openssl_decrypt(
        $ciphertext, 'aes-256-gcm', $key,
        OPENSSL_RAW_DATA, $iv, $tag
    );

    if ($plaintext === false) {
        // Tag mismatch -> tampering detected. Fail closed, isolated exception,
        // never a raw fatal crash that could leak a stack trace.
        throw new RuntimeException('AEAD authentication failed: payload rejected.');
    }

    return $plaintext;
}
?>
