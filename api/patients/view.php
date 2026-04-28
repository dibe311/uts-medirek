<?php
require_once '../config/app.php';
require_once '../config/database.php';
requireRole(['admin','dokter','perawat']);

$db = getDB();
$id = (int)($_GET['id'] ?? 0);

// BUG FIX: tambah AND is_active = 1 agar pasien yang soft-deleted tidak bisa diakses via URL langsung
$patient = $db->prepare("SELECT * FROM patients WHERE id = ? AND is_active = 1");
$patient->execute([$id]);
$patient = $patient->fetch();
if (!$patient) { flashMessage('error', 'Pasien tidak ditemukan.'); redirect('patients'); }

// Medical records
$records = $db->prepare("
    SELECT mr.*, u.name AS doctor_name
    FROM medical_records mr
    LEFT JOIN users u ON mr.doctor_id = u.id
    WHERE mr.patient_id = ?
    ORDER BY mr.visit_date DESC
    LIMIT 10
");
$records->execute([$id]);
$records = $records->fetchAll();

// Last initial check
$lastCheck = $db->prepare("SELECT ic.* FROM initial_checks ic WHERE ic.patient_id = ? ORDER BY checked_at DESC LIMIT 1");
$lastCheck->execute([$id]);
$lastCheck = $lastCheck->fetch();

$pageTitle = $patient['name'];
$activeMenu = 'patients';
?>
<?php require_once '../includes/header.php'; ?>
<div class="app-layout">
    <?php require_once '../includes/sidebar.php'; ?>
    <div class="main-content">
        <div class="topbar">
            <span class="topbar-title"><?= sanitize($patient['name']) ?></span>
            <div class="topbar-actions">
                <?php if (hasRole(['admin','perawat'])): ?>
                <a href="<?= BASE_URL ?>/patients/edit?id=<?= $id ?>" class="btn btn-outline btn-sm">Edit Data</a>
                <?php endif; ?>
                <a href="<?= BASE_URL ?>/patients" class="btn btn-ghost btn-sm">← Kembali</a>
            </div>
        </div>
        <div class="page-content">

            <!-- Patient header card -->
            <div class="patient-header">
                <div class="patient-avatar"><?= strtoupper(substr($patient['name'], 0, 2)) ?></div>
                <div>
                    <h2 style="font-size:1.15rem;font-weight:700;color:var(--slate-800)"><?= sanitize($patient['name']) ?></h2>
                    <div style="display:flex;align-items:center;gap:8px;margin-top:4px">
                        <span class="badge <?= $patient['insurance_type'] === 'BPJS' ? 'badge-done' : 'badge-draft' ?>"><?= sanitize($patient['insurance_type']) ?></span>
                        <?php if ($patient['allergy']): ?>
                        <span class="badge badge-cancelled" style="background:var(--red-50);color:var(--red-500)">⚠ Alergi</span>
                        <?php endif; ?>
                    </div>
                </div>
                <div class="patient-meta" style="margin-left:auto">
                    <div class="patient-meta-item">
                        <span class="meta-label">NIK</span>
                        <span class="meta-value"><?= sanitize($patient['nik']) ?></span>
                    </div>
                    <div class="patient-meta-item">
                        <span class="meta-label">Usia</span>
                        <span class="meta-value"><?= calculateAge($patient['birth_date']) ?> tahun</span>
                    </div>
                    <div class="patient-meta-item">
                        <span class="meta-label">Gender</span>
                        <span class="meta-value"><?= $patient['gender'] === 'L' ? 'Laki-laki' : 'Perempuan' ?></span>
                    </div>
                    <div class="patient-meta-item">
                        <span class="meta-label">Gol. Darah</span>
                        <span class="meta-value"><?= $patient['blood_type'] === 'unknown' ? '—' : sanitize($patient['blood_type']) ?></span>
                    </div>
                    <div class="patient-meta-item">
                        <span class="meta-label">Telepon</span>
                        <span class="meta-value"><?= sanitize($patient['phone'] ?? '—') ?></span>
                    </div>
                </div>
            </div>

            <div class="two-col-grid">
                <!-- Detail Pasien -->
                <div>
                    <div class="card" style="margin-bottom:16px">
                        <div class="card-header"><h3 class="card-title">Informasi Lengkap</h3></div>
                        <div class="card-body">
                            <dl class="info-dl">
                                <dt>Alamat</dt><dd><?= sanitize($patient['address'] ?? '—') ?></dd>
                                <dt>Email</dt><dd><?= sanitize($patient['email'] ?? '—') ?></dd>
                                <dt>No. Asuransi</dt><dd><?= sanitize($patient['insurance_number'] ?? '—') ?></dd>
                                <dt>Tanggal Lahir</dt><dd><?= date('d F Y', strtotime($patient['birth_date'])) ?></dd>
                                <dt>Terdaftar</dt><dd><?= date('d F Y', strtotime($patient['created_at'])) ?></dd>
                                <?php if ($patient['allergy']): ?>
                                <dt style="color:var(--red-500)">⚠ Alergi</dt>
                                <dd style="color:var(--red-500);font-weight:600"><?= sanitize($patient['allergy']) ?></dd>
                                <?php endif; ?>
                            </dl>
                        </div>
                    </div>

                    <?php if ($lastCheck): ?>
                    <div class="card">
                        <div class="card-header">
                            <h3 class="card-title">Tanda Vital Terakhir</h3>
                            <span class="text-xs text-muted"><?= date('d/m/Y H:i', strtotime($lastCheck['checked_at'])) ?></span>
                        </div>
                        <div class="card-body">
                            <div class="vitals-grid">
                                <?php if ($lastCheck['blood_pressure']): ?>
                                <div class="vital-item">
                                    <div class="vital-value"><?= sanitize($lastCheck['blood_pressure']) ?> <span class="vital-unit">mmHg</span></div>
                                    <div class="vital-label">Tekanan Darah</div>
                                </div>
                                <?php endif; ?>
                                <?php if ($lastCheck['temperature']): ?>
                                <div class="vital-item">
                                    <div class="vital-value"><?= $lastCheck['temperature'] ?><span class="vital-unit">°C</span></div>
                                    <div class="vital-label">Suhu</div>
                                </div>
                                <?php endif; ?>
                                <?php if ($lastCheck['pulse']): ?>
                                <div class="vital-item">
                                    <div class="vital-value"><?= $lastCheck['pulse'] ?> <span class="vital-unit">bpm</span></div>
                                    <div class="vital-label">Nadi</div>
                                </div>
                                <?php endif; ?>
                                <?php if ($lastCheck['oxygen_saturation']): ?>
                                <div class="vital-item">
                                    <div class="vital-value"><?= $lastCheck['oxygen_saturation'] ?><span class="vital-unit">%</span></div>
                                    <div class="vital-label">SpO₂</div>
                                </div>
                                <?php endif; ?>
                            </div>
                            <?php if ($lastCheck['chief_complaint']): ?>
                            <div style="background:var(--amber-50);border:1px solid #fde68a;border-radius:var(--radius);padding:12px;margin-top:8px">
                                <div class="text-xs" style="font-weight:700;color:#92400e;margin-bottom:4px">KELUHAN UTAMA</div>
                                <div class="text-sm"><?= sanitize($lastCheck['chief_complaint']) ?></div>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                    <?php endif; ?>
                </div>

                <!-- Riwayat Rekam Medis -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">Riwayat Kunjungan</h3>
                        <span class="badge badge-waiting" style="background:var(--blue-50);color:var(--blue-600)"><?= count($records) ?> kunjungan</span>
                    </div>
                    <div class="card-body">
                        <?php if ($records): ?>
                        <div class="record-timeline">
                            <?php foreach ($records as $r): ?>
                            <div class="timeline-item">
                                <div class="timeline-date"><?= date('d F Y', strtotime($r['visit_date'])) ?></div>
                                <div class="timeline-card">
                                    <div style="display:flex;justify-content:space-between;margin-bottom:8px">
                                        <span class="text-sm font-semibold">Dr. <?= sanitize($r['doctor_name']) ?></span>
                                        <?php if ($r['icd_code']): ?>
                                        <span class="badge badge-waiting" style="font-size:.65rem"><?= sanitize($r['icd_code']) ?></span>
                                        <?php endif; ?>
                                    </div>
                                    <div class="text-xs text-muted" style="margin-bottom:4px">DIAGNOSA</div>
                                    <div class="text-sm font-semibold" style="margin-bottom:8px"><?= sanitize($r['diagnosis']) ?></div>
                                    <?php if ($r['prescription']): ?>
                                    <div class="text-xs text-muted" style="margin-bottom:4px">RESEP</div>
                                    <div class="text-sm"><?= sanitize($r['prescription']) ?></div>
                                    <?php endif; ?>
                                    <div style="margin-top:8px">
                                        <a href="<?= BASE_URL ?>/medical_records/view?id=<?= $r['id'] ?>" class="btn btn-ghost btn-sm">Lihat Detail</a>
                                    </div>
                                </div>
                            </div>
                            <?php endforeach; ?>
                        </div>
                        <?php else: ?>
                        <div class="empty-state" style="padding:32px 0">
                            <p class="empty-state-title">Belum ada riwayat kunjungan</p>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
<?php require_once '../includes/footer.php'; ?>
