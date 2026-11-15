<?php
require_once 'functions.php';
require_once 'db.php';
session_start();
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Method not allowed.']);
    exit;
}

$identifier = trim($_POST['identifier'] ?? '');
$password   = $_POST['password'] ?? '';

if (!$identifier || !$password) {
    echo json_encode(['success' => false, 'message' => 'All fields are required.']);
    exit;
}

$result = ['success' => false, 'message' => 'Invalid credentials.'];

try {
    $stmt = DB::get()->prepare(
        'SELECT id_user, username, email, parola_hash, activ
         FROM useri
         WHERE username = :u OR email = :e
         LIMIT 1'
    );
    $stmt->execute([':u' => $identifier, ':e' => $identifier]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['parola_hash'])) {
        if (!$user['activ']) {
            $result = ['success' => false, 'message' => 'This account has been deactivated.'];
        } else {
            session_regenerate_id(true);
            $_SESSION['user_id']  = (int) $user['id_user'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['email']    = $user['email'];
            $result = ['success' => true, 'username' => $user['username']];
        }
    }
} catch (PDOException $e) {
    error_log('[BlitzIQ] login: ' . $e->getMessage());
    $result = ['success' => false, 'message' => 'A database error occurred. Please try again.'];
} catch (RuntimeException $e) {
    $result = ['success' => false, 'message' => $e->getMessage()];
} finally {
    DB::close();
}

echo json_encode($result);
