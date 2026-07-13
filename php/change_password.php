<?php
require_once 'functions.php';
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

$users   = loadUsers();
$updated = false;

foreach ($users as &$u) {
    $userId = $u['id'] ?? $u['username'];
    if ($userId == $_SESSION['user_id']) {
        if (password_verify($newPassword, $u['password_hash'])) {
            echo json_encode(['success' => false, 'message' => 'New password must be different from the current one.']);
            exit;
        }

        $u['password_hash'] = password_hash($newPassword, PASSWORD_BCRYPT);
        $updated = true;
        break;
    }
}
unset($u);

if (!$updated) {
    echo json_encode(['success' => false, 'message' => 'User not found.']);
    exit;
}

saveUsers($users);

echo json_encode(['success' => true, 'message' => 'Password updated successfully.']);
