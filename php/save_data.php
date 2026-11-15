<?php
require_once __DIR__ . '/db.php';
session_start();

if (!isset($_SESSION['user_id'])) {
    header('Content-Type: application/json');
    echo json_encode(['success' => false, 'message' => 'Not authenticated']);
    exit;
}

$dir = dirname(__DIR__) . '/data';
if (!is_dir($dir)) {
    mkdir($dir, 0777, true);
}

$file = $dir . '/user_' . $_SESSION['user_id'] . '_data.json';

header('Content-Type: application/json');

function syncQuizzesToDb(int $userId, ?array $quizzes): bool
{
    if ($quizzes === null) {
        return true;
    }

    $num = fn($v, int $min, int $max, int $def): int =>
        max($min, min($max, is_numeric($v) ? (int) $v : $def));

    try {
        $pdo = DB::get();
        $pdo->beginTransaction();

        $categorii  = $pdo->query('SELECT denumire, id_categorie FROM categorii')->fetchAll(PDO::FETCH_KEY_PAIR);

        $upsert = $pdo->prepare(
            'INSERT INTO quizuri
                (id_local, titlu, descriere, limba, id_categorie, id_autor,
                 vizibilitate, status, timp_limita, nr_intrebari, nr_incercari, scor_trecere, puncte_raspuns)
             VALUES
                (:local, :titlu, :descr, :limba, :cat, :autor,
                 :viz, :status, :timp, :nr, :inc, :scor, :pct)
             ON DUPLICATE KEY UPDATE
                titlu = VALUES(titlu), descriere = VALUES(descriere), limba = VALUES(limba),
                id_categorie = VALUES(id_categorie),
                vizibilitate = VALUES(vizibilitate), status = VALUES(status),
                timp_limita = VALUES(timp_limita), nr_intrebari = VALUES(nr_intrebari),
                nr_incercari = VALUES(nr_incercari), scor_trecere = VALUES(scor_trecere),
                puncte_raspuns = VALUES(puncte_raspuns)'
        );

        $keep = [];
        foreach ($quizzes as $q) {
            if (!is_array($q) || empty($q['id'])) {
                continue;
            }
            $local  = substr((string) $q['id'], 0, 20);
            $keep[] = $local;

            $titlu = trim((string) ($q['name'] ?? ''));
            $nrQ   = isset($q['questions']) && is_array($q['questions']) ? count($q['questions']) : 0;
            $viz   = in_array($q['visibility'] ?? '', ['public', 'private', 'draft'], true) ? $q['visibility'] : 'public';

            $upsert->execute([
                ':local'  => $local,
                ':titlu'  => mb_substr($titlu !== '' ? $titlu : 'Untitled', 0, 100),
                ':descr'  => mb_substr((string) ($q['description'] ?? ''), 0, 500),
                ':limba'  => mb_substr((string) ($q['language'] ?? ''), 0, 30),
                ':cat'    => $categorii[$q['subject'] ?? ''] ?? null,
                ':autor'  => $userId,
                ':viz'    => $viz,
                ':status' => ($q['status'] ?? '') === 'published' ? 'published' : 'draft',
                ':timp'   => $num($q['timePerQ'] ?? null, 1, 300, 30),
                ':nr'     => max(1, $nrQ ?: $num($q['questionCount'] ?? null, 1, 100, 10)),
                ':inc'    => $num($q['attempts'] ?? null, 1, 10, 1),
                ':scor'   => $num($q['passScore'] ?? null, 0, 100, 60),
                ':pct'    => $num($q['points'] ?? null, 1, 100000, 10),
            ]);
        }

        $sql = 'DELETE FROM quizuri
                WHERE id_autor = ? AND id_local IS NOT NULL
                  AND id_quiz NOT IN (SELECT id_quiz FROM rezultate)';
        $params = [$userId];
        if ($keep) {
            $sql .= ' AND id_local NOT IN (' . implode(',', array_fill(0, count($keep), '?')) . ')';
            $params = array_merge($params, $keep);
        }
        $pdo->prepare($sql)->execute($params);

        $pdo->commit();
        return true;
    } catch (Throwable $e) {
        if (isset($pdo) && $pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('[BlitzIQ] syncQuizzesToDb: ' . $e->getMessage());
        return false;
    } finally {
        DB::close();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $raw = file_get_contents('php://input');
    $data = json_decode($raw, true);

    if (!$data) {
        echo json_encode(['success' => false, 'message' => 'Invalid data']);
        exit;
    }

    $allowed = ['quizzes', 'folders', 'saved', 'notifs', 'history'];
    $clean = [];
    foreach ($allowed as $key) {
        if (isset($data[$key])) {
            $clean[$key] = $data[$key];
        }
    }

    file_put_contents($file, json_encode($clean, JSON_PRETTY_PRINT));

    $dbOk = syncQuizzesToDb(
        (int) $_SESSION['user_id'],
        isset($clean['quizzes']) && is_array($clean['quizzes']) ? $clean['quizzes'] : null
    );

    echo json_encode(['success' => true, 'db' => $dbOk]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    if (file_exists($file)) {
        $content = file_get_contents($file);
        $data = json_decode($content, true);
        echo json_encode(['success' => true, 'data' => $data]);
    } else {
        echo json_encode(['success' => true, 'data' => [
            'quizzes' => [],
            'folders' => [],
            'saved' => [],
            'notifs' => [],
            'history' => []
        ]]);
    }
    exit;
}

echo json_encode(['success' => false, 'message' => 'Method not allowed.']);
