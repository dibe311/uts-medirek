<?php
/**
 * includes/layout.php
 * Shell layout utama — dipakai oleh semua halaman inner via ob_start() pattern.
 * Variabel yang harus di-set sebelum require:
 *   $pageTitle   (string)  — judul tab browser
 *   $activeMenu  (string)  — kunci menu sidebar yang aktif
 *   $pageContent (string)  — HTML konten halaman dari ob_get_clean()
 * Variabel opsional:
 *   $extraHead   (string)  — tag <link>/<meta> tambahan di <head>
 *   $extraScript (string)  — tag <script> tambahan sebelum </body>
 */
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= sanitize($pageTitle ?? 'Halaman') ?> — <?= APP_NAME ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="<?= BASE_URL ?>/public/css/app.css">
    <link rel="stylesheet" href="<?= BASE_URL ?>/public/css/inner.css">
    <?php if (!empty($extraHead)) echo $extraHead; ?>
</head>
<body>
<div class="app-layout">
    <?php require_once __DIR__ . '/sidebar.php'; ?>
    <div class="main-content">
        <!-- Topbar -->
        <div class="topbar">
            <div class="flex items-center gap-2">
                <button id="sidebarToggle" class="btn btn-ghost btn-icon">
                    <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M3 5a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 5a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 5a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd"/>
                    </svg>
                </button>
                <span class="topbar-title"><?= sanitize($pageTitle ?? '') ?></span>
            </div>
            <div class="topbar-actions">
                <span class="topbar-date"><?= date('d F Y') ?></span>
                <span id="liveClock" class="text-sm font-semibold" style="color:var(--gray-600)"></span>
            </div>
        </div>
        <!-- Page Content -->
        <div class="page-content">
            <?php echo $pageContent ?? ''; ?>
        </div>
    </div>
</div>
<script src="<?= BASE_URL ?>/public/js/app.js"></script>
<?php if (!empty($extraScript)) echo $extraScript; ?>
</body>
</html>
