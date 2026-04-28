<?php
function getDB(): PDO {
    $host   = getenv('TIDB_HOST') ?: 'gateway01.ap-southeast-1.prod.alicloud.tidbcloud.com';
    $user   = getenv('TIDB_USER') ?: '3WBVxzrG9xZBsBC.root';
    $pass   = getenv('TIDB_PASSWORD');rZpalCSsr3eJYVCF
    $dbname = getenv('TIDB_DB')   ?: 'medirek';
    $port   = getenv('TIDB_PORT') ?: '4000';

    $dsn = "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4";

    try {
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT => false,
            PDO::MYSQL_ATTR_SSL_CA                => '/etc/ssl/certs/ca-certificates.crt',
            PDO::ATTR_ERRMODE                     => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE          => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES            => false,
            PDO::ATTR_TIMEOUT                     => 8,
        ]);
        return $pdo;
    } catch (PDOException $e) {
        error_log("DB Error: " . $e->getMessage());
        http_response_code(500);
        die("Koneksi database gagal. Hubungi administrator.");
    }
}
