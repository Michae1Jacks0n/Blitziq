<?php
require_once 'functions.php';
require_once 'db.php';
session_start();
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'message' => 'Method not allowed.']);
    exit;
}

$username = trim($_POST['username'] ?? '');
$email    = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';
$confirm  = $_POST['confirm'] ?? '';

if (!$username || !$email || !$password || !$confirm) {
    echo json_encode(['success' => false, 'message' => 'All fields are required.']);
    exit;
}

if (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
    echo json_encode(['success' => false, 'message' => 'Username must be 3-30 characters (letters, numbers, underscores).']);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 100) {
    echo json_encode(['success' => false, 'message' => 'Invalid email address.']);
    exit;
}

if (strlen($password) < 8) {
    echo json_encode(['success' => false, 'message' => 'Password must be at least 8 characters.']);
    exit;
}

if ($password !== $confirm) {
    echo json_encode(['success' => false, 'message' => 'Passwords do not match.']);
    exit;
}

$result = ['success' => false, 'message' => 'Registration failed.'];

try {
    $pdo = DB::get();

    $check = $pdo->prepare('SELECT username, email FROM useri WHERE username = :u OR email = :e');
    $check->execute([':u' => $username, ':e' => $email]);
    $taken = null;
    foreach ($check->fetchAll() as $row) {
        if (strcasecmp($row['username'], $username) === 0) {
            $taken = 'Username already taken.';
            break;
        }
        $taken = 'Email already registered.';
    }

    if ($taken) {
        $result = ['success' => false, 'message' => $taken];
    } else {
        $insert = $pdo->prepare('INSERT INTO useri (username, email, parola_hash) VALUES (:u, :e, :p)');
        $insert->execute([
            ':u' => $username,
            ':e' => $email,
            ':p' => password_hash($password, PASSWORD_BCRYPT),
        ]);

        session_regenerate_id(true);
        $_SESSION['user_id']  = (int) $pdo->lastInsertId();
        $_SESSION['username'] = $username;
        $_SESSION['email']    = $email;
        $result = ['success' => true, 'username' => $username];
    }
} catch (PDOException $e) {

    if (($e->errorInfo[1] ?? 0) === 1062) {
        $result = ['success' => false, 'message' => 'Username or email already taken.'];
    } else {
        error_log('[BlitzIQ] register: ' . $e->getMessage());
        $result = ['success' => false, 'message' => 'A database error occurred. Please try again.'];
    }
} catch (RuntimeException $e) {
    $result = ['success' => false, 'message' => $e->getMessage()];
} finally {
    DB::close();
}

echo json_encode($result);
