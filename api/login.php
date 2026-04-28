<?php
/**
 * login.php
 * TASK 4: Full authentication audit & fix
 * - password_verify() with proper bcrypt
 * - $_SESSION stores id, name, email, role correctly
 * - Login blocked for inactive accounts
 */
require_once 'config/app.php';
require_once 'config/database.php';

if (isLoggedIn()) redirect('dashboard');

$flash   = getFlash();
$error   = '';
$oldEmail = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = trim($_POST['email']    ?? '');
    $password =       $_POST['password'] ?? '';

    // Basic presence check
    if (empty($email) || empty($password)) {
        $error = 'Email dan password wajib diisi.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = 'Format email tidak valid.';
    } else {
        $db   = getDB();

        $stmt = $db->prepare(
            "SELECT id, name, email, password, role, is_active FROM users WHERE email = ? LIMIT 1"
        );
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $error = 'Email atau password tidak valid.';
        } elseif (!(bool)$user['is_active']) {
            $error = 'Akun Anda telah dinonaktifkan. Hubungi administrator.';
        } elseif (!password_verify($password, $user['password'])) {
            $error = 'Email atau password tidak valid.';
        } else {
            // --- Success: build session ---
            session_regenerate_id(true); // prevent session fixation

            $_SESSION['user'] = [
                'id'    => (int)$user['id'],
                'name'  => $user['name'],
                'email' => $user['email'],
                'role'  => $user['role'],
            ];

            // Update last_login
            $db->prepare("UPDATE users SET last_login = NOW() WHERE id = ?")
               ->execute([$user['id']]);

            flashMessage('success', 'Selamat datang, ' . $user['name'] . '!');
            redirect('dashboard');
        }
    }

    $oldEmail = sanitize($email);
}

$timeout = isset($_GET['timeout']);
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Masuk — <?= APP_NAME ?></title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="<?= BASE_URL ?>/public/css/app.css">
  <link rel="stylesheet" href="<?= BASE_URL ?>/public/css/auth.css">
</head>
<body class="auth-body">

<div class="auth-wrapper">
  <!-- LEFT -->
  <div class="auth-panel-left">
    <div class="auth-brand">
      <div class="auth-brand-icon">
        <svg width="20" height="20" viewBox="0 0 28 28" fill="none">
          <path d="M14 4v20M4 14h20" stroke="white" stroke-width="2.5" stroke-linecap="round"/>
        </svg>
      </div>
      <span class="auth-brand-name"><?= APP_NAME ?></span>
    </div>

    <div class="auth-hero">
      <h2 class="auth-hero-title">Rekam medis pasien,<br><em>lebih efisien dari sebelumnya.</em></h2>
      <p class="auth-hero-desc">Akses terpusat untuk dokter, perawat, dan tenaga medis lainnya.</p>
    </div>

    <div class="auth-features">
      <div class="auth-feature-item">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
        Dashboard berbasis role
      </div>
      <div class="auth-feature-item">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
        Sesi aman dengan timeout otomatis
      </div>
      <div class="auth-feature-item">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
        Rekam medis terintegrasi & aman
      </div>
    </div>
  </div>

  <!-- RIGHT -->
  <div class="auth-panel-right">
    <h1 class="auth-form-title">Masuk ke Sistem</h1>
    <p class="auth-form-sub">Gunakan kredensial akun Anda</p>

    <?php if ($timeout): ?>
    <div class="alert alert-warning">
      <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
      Sesi Anda telah berakhir karena tidak aktif. Silakan masuk kembali.
    </div>
    <?php endif; ?>

    <?php if ($flash && $flash['type'] === 'success'): ?>
    <div class="alert alert-success">
      <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
      <?= sanitize($flash['message']) ?>
    </div>
    <?php endif; ?>

    <?php if ($error): ?>
    <div class="alert alert-error">
      <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
      <?= sanitize($error) ?>
    </div>
    <?php endif; ?>

    <form method="POST" action="" novalidate>
      <div class="form-group">
        <label class="form-label" for="email">Email</label>
        <input class="form-control" type="email" id="email" name="email"
               placeholder="email@medirek.id"
               value="<?= $oldEmail ?>" required autofocus autocomplete="username">
      </div>
      <div class="form-group">
        <label class="form-label" for="password">Password</label>
        <input class="form-control" type="password" id="password" name="password"
               placeholder="••••••••" required autocomplete="current-password">
      </div>
      <button type="submit" class="btn btn-navy btn-lg w-full" style="justify-content:center;margin-top:6px">
        Masuk ke Dashboard
      </button>
    </form>

    <p style="text-align:center;margin-top:16px;font-size:13px;color:var(--gray-500)">
      Belum punya akun?
      <a href="<?= BASE_URL ?>/register" style="font-weight:600">Daftar sekarang</a>
    </p>

    <!-- Demo accounts — TASK 4: always-correct credentials -->
    <div class="demo-accounts">
      <div class="demo-accounts-title">Akun Demo (password: <strong>password</strong>)</div>
      <div class="demo-row" data-email="admin@medirek.id" data-password="password">
        <span class="demo-role">Admin</span>
        <span>admin@medirek.id</span>
        <span class="demo-pass">password</span>
      </div>
      <div class="demo-row" data-email="dokter@medirek.id" data-password="password">
        <span class="demo-role">Dokter</span>
        <span>dokter@medirek.id</span>
        <span class="demo-pass">password</span>
      </div>
      <div class="demo-row" data-email="perawat@medirek.id" data-password="password">
        <span class="demo-role">Perawat</span>
        <span>perawat@medirek.id</span>
        <span class="demo-pass">password</span>
      </div>
      <div class="demo-row" data-email="pasien@medirek.id" data-password="password">
        <span class="demo-role">Pasien</span>
        <span>pasien@medirek.id</span>
        <span class="demo-pass">password</span>
      </div>
    </div>
  </div>
</div>

<script src="<?= BASE_URL ?>/public/js/app.js"></script>
</body>
</html>