<?php
function getDB() {
    $host     = getenv('TIDB_HOST')     ? getenv('TIDB_HOST')     : 'gateway01.ap-southeast-1.prod.alicloud.tidbcloud.com';
    $port     = getenv('TIDB_PORT')     ? getenv('TIDB_PORT')     : '4000';
    $dbname   = getenv('TIDB_DB')       ? getenv('TIDB_DB')       : 'medirek';
    $username = getenv('TIDB_USER')     ? getenv('TIDB_USER')     : '3WBVxzrG9xZBsBC.root';
    $password = getenv('TIDB_PASSWORD') ? getenv('TIDB_PASSWORD') : 'rZpalCSsr3eJYVCF';

    $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";

    $options = array(
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    );

    // TiDB Cloud Serverless: tambah SSL hanya jika file CA tersedia
    $ssl_ca = '/etc/ssl/certs/ca-certificates.crt';
    if (file_exists($ssl_ca)) {
        $options[PDO::MYSQL_ATTR_SSL_CA] = $ssl_ca;
        $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = false;
    }

    try {
        $pdo = new PDO($dsn, $username, $password, $options);
        return $pdo;
    } catch (PDOException $e) {
        error_log("DB Connection Error: " . $e->getMessage());
        http_response_code(500);
        die("Koneksi database gagal. Cek konfigurasi environment variable.");
    }
}
