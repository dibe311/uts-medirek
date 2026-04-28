<?php
function getDB() {
    $host     = 'gateway01.ap-southeast-1.prod.alicloud.tidbcloud.com';
    $port     = '4000';
    $dbname   = 'medirek';
    $username = '3WBVxzrG9xZBsBC.root';
    $password = 'n4RcjqVuNQNiRPcv';

    $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";

    $options = array(
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
        PDO::MYSQL_ATTR_SSL_CA       => '/etc/ssl/certs/ca-certificates.crt',
        PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
    );

    try {
        return new PDO($dsn, $username, $password, $options);
    } catch (PDOException $e) {
        error_log("DB Connection Error: " . $e->getMessage());
        http_response_code(500);
        die("Koneksi database gagal. Cek konfigurasi environment variable.");
    }
}