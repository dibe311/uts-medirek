<?php
ob_start();

define('APP_NAME', 'MediRek');
define('APP_VERSION', '1.0.0');
// APP_URL: kosongkan ('') untuk Vercel/production. Untuk XAMPP lokal: 'http://localhost/medirek/api'
define('BASE_URL', rtrim(getenv('APP_URL') ? getenv('APP_URL') : '', '/'));
define('SESSION_TIMEOUT', 3600);

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params(array(
        'lifetime' => SESSION_TIMEOUT,
        'path'     => '/',
        'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
        'httponly' => true,
        'samesite' => 'Strict',
    ));
    session_start();
}

if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
    session_unset();
    session_destroy();
    header('Location: ' . BASE_URL . '/login?timeout=1');
    exit;
}
$_SESSION['last_activity'] = time();

function currentUser() {
    return isset($_SESSION['user']) ? $_SESSION['user'] : null;
}

function isLoggedIn() {
    return isset($_SESSION['user']);
}

function hasRole($roles) {
    $user = currentUser();
    if (!$user) return false;
    if (is_string($roles)) $roles = array($roles);
    return in_array($user['role'], $roles);
}

function requireAuth() {
    if (!isLoggedIn()) {
        header('Location: ' . BASE_URL . '/login');
        exit;
    }
}

function requireRole($roles) {
    requireAuth();
    if (!hasRole($roles)) {
        header('Location: ' . BASE_URL . '/dashboard?error=unauthorized');
        exit;
    }
}

function redirect($path) {
    header('Location: ' . BASE_URL . '/' . ltrim($path, '/'));
    exit;
}

function sanitize($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function flashMessage($type, $message) {
    $_SESSION['flash'] = array('type' => $type, 'message' => $message);
}

function getFlash() {
    if (isset($_SESSION['flash'])) {
        $flash = $_SESSION['flash'];
        unset($_SESSION['flash']);
        return $flash;
    }
    return null;
}

function generateQueueNumber($pdo, $date) {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM queues WHERE queue_date = ?");
    $stmt->execute(array($date));
    $count = (int)$stmt->fetchColumn();
    return 'A' . str_pad($count + 1, 3, '0', STR_PAD_LEFT);
}

function calculateAge($birthDate) {
    return (int)(new DateTime($birthDate))->diff(new DateTime())->y;
}

function queueStatusLabel($status) {
    $labels = array(
        'waiting'     => 'Menunggu',
        'called'      => 'Dipanggil',
        'in_progress' => 'Diperiksa',
        'done'        => 'Selesai',
        'cancelled'   => 'Batal',
    );
    return isset($labels[$status]) ? $labels[$status] : $status;
}
