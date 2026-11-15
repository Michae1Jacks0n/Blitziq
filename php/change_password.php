<?php
require_once 'functions.php';
require_once 'db.php';
session_start();
header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    echo json_encode(['success' => false, 'message' => 'Not authenticated.']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Method not allowed.']);
    exit;
}

$newPassword     = $_POST['new_password'] ?? '';
$confirmPassword = $_POST['confirm_password'] ?? '';

if (!$newPassword || !$confirmPassword) {
    echo json_encode(['success' => false, 'message' => 'All fields are required.']);
    exit;
}

if (strlen($newPassword) < 8) {
    echo json_encode(['success' => false, 'message' => 'New password must be at least 8 characters.']);
    exit;
}

if ($newPassword !== $confirmPassword) {
    echo json_encode(['success' => false, 'message' => 'New passwords do not match.']);
    exit;
}

$result = ['success' => false, 'message' => 'Could not update the password.'];

try {
    $pdo = DB::get();

    $select = $pdo->prepare('SELECT parola_hash FROM useri WHERE id_user = :id AND activ = 1');
    $select->execute([':id' => (int) $_SESSION['user_id']]);
    $user = $select->fetch();

    if (!$user) {
        $result = ['success' => false, 'message' => 'User not found.'];
    } elseif (password_verify($newPassword, $user['parola_hash'])) {
        $result = ['success' => false, 'message' => 'New password must be different from the current one.'];
    } else {
        $update = $pdo->prepare('UPDATE useri SET parola_hash = :h WHERE id_user = :id');
        $update->execute([
            ':h'  => password_hash($newPassword, PASSWORD_BCRYPT),
            ':id' => (int) $_SESSION['user_id'],
        ]);
        $result = ['success' => true, 'message' => 'Password updated successfully.'];
    }
} catch (PDOException $e) {
    error_log('[BlitzIQ] change_password: ' . $e->getMessage());
    $result = ['success' => false, 'message' => 'A database error occurred. Please try again.'];
} catch (RuntimeException $e) {
    $result = ['success' => false, 'message' => $e->getMessage()];
} finally {
    DB::close();
}

echo json_encode($result);
