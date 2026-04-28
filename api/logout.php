<?php
require_once 'config/app.php';
session_unset();
session_destroy();
// Fix: redirect ke /login bukan /login.php agar cocok dengan vercel routes
header('Location: ' . BASE_URL . '/login');
exit;
