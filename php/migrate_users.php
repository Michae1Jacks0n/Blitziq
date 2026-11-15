<?php
if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('CLI only.');
}

require_once __DIR__ . '/db.php';

$dataDir  = dirname(__DIR__) . '/data';
$jsonFile = $dataDir . '/users.json';

if (!file_exists($jsonFile)) {
    exit("Nu exista $jsonFile - nimic de migrat.\n");
}

$users = json_decode(file_get_contents($jsonFile), true);
if (!is_array($users)) {
    exit("users.json este invalid.\n");
}

try {
    $pdo = DB::get();
} catch (RuntimeException $e) {
    exit('Eroare: ' . $e->getMessage() . "\n");
}

$find   = $pdo->prepare('SELECT id_user FROM useri WHERE username = :u OR email = :e LIMIT 1');
$insert = $pdo->prepare('INSERT INTO useri (username, email, parola_hash) VALUES (:u, :e, :p)');

$added = $skipped = $copied = 0;

foreach ($users as $u) {
    $oldId = $u['id'] ?? $u['username'];
    $find->execute([':u' => $u['username'], ':e' => $u['email']]);
    $row = $find->fetch();

    if ($row) {
        $newId = (int) $row['id_user'];
        $skipped++;
        echo "Exista deja: {$u['username']} (id $newId)\n";
    } else {
        try {
            $insert->execute([':u' => $u['username'], ':e' => $u['email'], ':p' => $u['password_hash']]);
        } catch (PDOException $e) {
            echo "EROARE la {$u['username']}: " . $e->getMessage() . "\n";
            continue;
        }
        $newId = (int) $pdo->lastInsertId();
        $added++;
        echo "Adaugat: {$u['username']} (id vechi $oldId -> id nou $newId)\n";
    }

    $src = "$dataDir/user_{$oldId}_data.json";
    $dst = "$dataDir/user_{$newId}_data.json";
    if (file_exists($src) && !file_exists($dst)) {
        copy($src, $dst);
        $copied++;
    }
}

DB::close();
echo "\nGata: $added adaugati, $skipped existau deja, $copied fisiere de date copiate.\n";
