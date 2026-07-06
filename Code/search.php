<?php
// search.php - Secure Refactor
// Fixes: Flaw A (SQL Injection) + Flaw B/C (Reflected XSS)
require_once 'db_config.php'; // now returns a PDO instance, least-privilege DB user

$keyword = $_GET['keyword'] ?? '';

// Parameterised query: value is sent separately from SQL structure,
// so it can never be interpreted as executable syntax.
$stmt = $pdo->prepare(
    'SELECT id, name, illness_history FROM patient_records WHERE name LIKE :kw'
);
$stmt->execute([':kw' => '%' . $keyword . '%']);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

if (count($rows) > 0) {
    foreach ($rows as $row) {
        // Context-aware output encoding: every value that lands in HTML
        // is passed through htmlspecialchars() before being echoed.
        echo '<div>Result found for keyword: ' .
            htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8') . '<br>';
        echo 'Patient: ' . htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8')
            . ' | History: ' . htmlspecialchars($row['illness_history'], ENT_QUOTES, 'UTF-8') . '</div><hr>';
    }
} else {
    echo 'No records found for: ' . htmlspecialchars($keyword, ENT_QUOTES, 'UTF-8');
}
?>
