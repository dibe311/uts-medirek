<?php
ob_start(); // Buffer output - prevents "headers already sent" errors

define('APP_NAME', 'MediRek');
define('APP_VERSION', '1.0.0');
// APP_URL: kosongkan ('') untuk Vercel/production. Untuk XAMPP lokal, set ke 'http://localhost/medirek/api'
define('BASE_URL', rtrim(getenv('APP_URL') ?: '', '/'));
define('SESSION_TIMEOUT', 3600);

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => SESSION_TIMEOUT,
        'path'     => '/',
        'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on',
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
    session_unset();
    session_destroy();
    header('Location: ' . BASE_URL . '/login?timeout=1');
    exit;
}
$_SESSION['last_activity'] = time();

function currentUser(): ?array {
    return $_SESSION['user'] ?? null;
}

function isLoggedIn(): bool {
    return isset($_SESSION['user']);
}

function hasRole(string|array $roles): bool {
    $user = currentUser();
    if (!$user) return false;
    if (is_string($roles)) $roles = [$roles];
    return in_array($user['role'], $roles);
}

function requireAuth(): void {
    if (!isLoggedIn()) {
        header('Location: ' . BASE_URL . '/login');
        exit;
    }
}

function requireRole(string|array $roles): void {
    requireAuth();
    if (!hasRole($roles)) {
        header('Location: ' . BASE_URL . '/dashboard?error=unauthorized');
        exit;
    }
}

function redirect(string $path): void {
    header('Location: ' . BASE_URL . '/' . ltrim($path, '/'));
    exit;
}

function sanitize(string $input): string {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function flashMessage(string $type, string $message): void {
    $_SESSION['flash'] = ['type' => $type, 'message' => $message];
}

function getFlash(): ?array {
    if (isset($_SESSION['flash'])) {
        $flash = $_SESSION['flash'];
        unset($_SESSION['flash']);
        return $flash;
    }
    return null;
}

function generateQueueNumber(PDO $pdo, string $date): string {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM queues WHERE queue_date = ?");
    $stmt->execute([$date]);
    $count = (int)$stmt->fetchColumn();
    return 'A' . str_pad($count + 1, 3, '0', STR_PAD_LEFT);
}

function calculateAge(string $birthDate): int {
    return (int)(new DateTime($birthDate))->diff(new DateTime())->y;
}
