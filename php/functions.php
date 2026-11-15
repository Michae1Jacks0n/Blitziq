<?php
function sendJson(array $data): void {
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

function requireAuth(): void {
    if (!isset($_SESSION['user_id'])) {
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            sendJson(['success' => false, 'message' => 'Not authenticated.']);
        }
        if (!empty($_SERVER['HTTP_ACCEPT']) && str_contains($_SERVER['HTTP_ACCEPT'], 'application/json')) {
            sendJson(['success' => false, 'message' => 'Not authenticated.']);
        }
        header('Location: index.php');
        exit;
    }
}
