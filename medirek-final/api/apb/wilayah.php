<?php
/**
 * apb/wilayah.php — Proxy server-side untuk API BPS
 *
 * Kenapa proxy ini diperlukan:
 *   Browser tidak boleh fetch langsung ke webapi.bps.go.id dari domain lain (CORS).
 *   PHP tidak punya batasan CORS — request dilakukan server-ke-server,
 *   lalu hasilnya dikembalikan ke browser dengan header yang benar.
 *
 * Endpoint:
 *   GET /apb/wilayah        → semua domain (provinsi + kabupaten)
 */

require_once __DIR__ . '/../config/app.php';

// Hanya izinkan GET
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    exit(json_encode(['error' => 'Method not allowed']));
}

$BPS_KEY = '4115c372d25a070339527ebbed71cc6a';
$url     = "https://webapi.bps.go.id/v1/api/domain/type/all/prov/00000/key/{$BPS_KEY}/";

// Coba ambil dari cache session agar tidak fetch BPS berkali-kali
// (opsional tapi membantu performa)
if (isset($_SESSION['bps_wilayah_cache'])) {
    header('Content-Type: application/json');
    header('X-Cache: HIT');
    echo $_SESSION['bps_wilayah_cache'];
    exit;
}

// Fetch ke BPS dari PHP (server-to-server, tidak kena CORS)
$ctx = stream_context_create([
    'http' => [
        'method'  => 'GET',
        'timeout' => 15,
        'header'  => "Accept: application/json\r\nUser-Agent: MediRek/1.0\r\n",
    ],
    'ssl' => [
        'verify_peer'      => false,
        'verify_peer_name' => false,
    ],
]);

$raw = @file_get_contents($url, false, $ctx);

if ($raw === false) {
    http_response_code(502);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Gagal menghubungi API BPS. Coba beberapa saat lagi.']);
    exit;
}

// Validasi response JSON dari BPS
$json = json_decode($raw, true);
if (!$json || ($json['status'] ?? '') !== 'OK') {
    http_response_code(502);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Response BPS tidak valid.', 'raw' => substr($raw, 0, 300)]);
    exit;
}

// Simpan di session cache (berlaku selama sesi user)
$_SESSION['bps_wilayah_cache'] = $raw;

header('Content-Type: application/json');
header('X-Cache: MISS');
echo $raw;
