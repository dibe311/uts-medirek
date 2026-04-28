<?php
/**
 * register.php
 * TASK 1: Multi-role registration
 * TASK 4: Hardened auth logic
 */
require_once 'config/app.php';
require_once 'config/database.php';

if (isLoggedIn()) redirect('dashboard');

// TASK 1: Allowed roles — server-side whitelist (prevents enum manipulation)
const ALLOWED_ROLES = ['admin', 'dokter', 'perawat', 'pasien'];

$errors = [];
$old    = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $old = [
        'name'     => trim($_POST['name']     ?? ''),
        'email'    => trim($_POST['email']    ?? ''),
        'phone'    => trim($_POST['phone']    ?? ''),
        'role'     => trim($_POST['role']     ?? 'pasien'),
        'province' => trim($_POST['province'] ?? ''),
        'province_name' => trim($_POST['province_name'] ?? ''),
        'city'     => trim($_POST['city']     ?? ''),
        'city_name' => trim($_POST['city_name'] ?? ''),
    ];
    $password = $_POST['password']         ?? '';
    $confirm  = $_POST['confirm_password'] ?? '';

    // --- Validation ---
    if (empty($old['name']))                         $errors['name']     = 'Nama wajib diisi.';
    elseif (strlen($old['name']) < 3)                $errors['name']     = 'Nama minimal 3 karakter.';

    if (empty($old['email']))                        $errors['email']    = 'Email wajib diisi.';
    elseif (!filter_var($old['email'], FILTER_VALIDATE_EMAIL)) $errors['email'] = 'Format email tidak valid.';

    if (strlen($password) < 6)                       $errors['password'] = 'Password minimal 6 karakter.';
    if ($password !== $confirm)                      $errors['confirm']  = 'Konfirmasi password tidak cocok.';

    // TASK 1: server-side role whitelist validation
    if (!in_array($old['role'], ALLOWED_ROLES, true)) {
        $errors['role'] = 'Role tidak valid.';
        $old['role']    = 'pasien'; // reset to safe default
    }

    // Province & city validation
    if (empty($old['province'])) $errors['province'] = 'Provinsi wajib dipilih.';
    if (empty($old['city']))     $errors['city']     = 'Kabupaten/Kota wajib dipilih.';

    if (!$errors) {
        $db = getDB();
        // Check email uniqueness
        $chk = $db->prepare("SELECT id FROM users WHERE email = ?");
        $chk->execute([$old['email']]);
        if ($chk->fetch()) {
            $errors['email'] = 'Email sudah terdaftar.';
        }
    }

    if (!$errors) {
        $db   = getDB();
        $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        $stmt = $db->prepare(
            "INSERT INTO users (name, email, password, phone, role, province_code, province_name, city_code, city_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        );
        $stmt->execute([$old['name'], $old['email'], $hash, $old['phone'], $old['role'],
                        $old['province'], $old['province_name'], $old['city'], $old['city_name']]);

        flashMessage('success', 'Akun berhasil dibuat. Silakan masuk.');
        redirect('login');
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Daftar — <?= APP_NAME ?></title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="<?= BASE_URL ?>/public/css/app.css">
  <link rel="stylesheet" href="<?= BASE_URL ?>/public/css/auth.css">
</head>
<body class="auth-body">

<div class="auth-wrapper">
  <!-- LEFT PANEL -->
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
      <h2 class="auth-hero-title">Sistem Rekam Medis<br><em>Terintegrasi</em></h2>
      <p class="auth-hero-desc">Platform digital untuk tenaga medis dan pasien dalam ekosistem layanan kesehatan yang efisien.</p>
    </div>

    <div class="auth-features">
      <div class="auth-feature-item">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
        Role akses berbasis jabatan
      </div>
      <div class="auth-feature-item">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
        Data rekam medis terenkripsi
      </div>
      <div class="auth-feature-item">
        <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
        Audit trail & keamanan sesi
      </div>
    </div>
  </div>

  <!-- RIGHT PANEL -->
  <div class="auth-panel-right">
    <h1 class="auth-form-title">Buat Akun</h1>
    <p class="auth-form-sub">Daftarkan akun Anda ke sistem <?= APP_NAME ?></p>

    <?php if ($errors): ?>
    <div class="alert alert-error">
      <svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
      <div>Mohon periksa kembali isian di bawah ini.</div>
    </div>
    <?php endif; ?>

    <form method="POST" action="" novalidate>
      <!-- Nama -->
      <div class="form-group">
        <label class="form-label" for="name">Nama Lengkap <span class="req">*</span></label>
        <input class="form-control <?= isset($errors['name']) ? 'error' : '' ?>"
               type="text" id="name" name="name"
               placeholder="Nama lengkap sesuai identitas"
               value="<?= sanitize($old['name'] ?? '') ?>" required autofocus>
        <?php if (isset($errors['name'])): ?>
          <div class="form-error-text"><?= sanitize($errors['name']) ?></div>
        <?php endif; ?>
      </div>

      <!-- Email -->
      <div class="form-group">
        <label class="form-label" for="email">Email <span class="req">*</span></label>
        <input class="form-control <?= isset($errors['email']) ? 'error' : '' ?>"
               type="email" id="email" name="email"
               placeholder="email@instansi.id"
               value="<?= sanitize($old['email'] ?? '') ?>" required>
        <?php if (isset($errors['email'])): ?>
          <div class="form-error-text"><?= sanitize($errors['email']) ?></div>
        <?php endif; ?>
      </div>

      <!-- Telepon -->
      <div class="form-group">
        <label class="form-label" for="phone">No. Telepon</label>
        <input class="form-control" type="tel" id="phone" name="phone"
               placeholder="08xxxxxxxxxx" value="<?= sanitize($old['phone'] ?? '') ?>">
      </div>

      <!-- Provinsi -->
      <div class="form-group">
        <label class="form-label" for="province">Provinsi <span class="req">*</span></label>
        <select class="form-control <?= isset($errors['province']) ? 'error' : '' ?>"
                id="province" name="province" required>
          <option value="">— Memuat provinsi… —</option>
        </select>
        <input type="hidden" id="province_name" name="province_name"
               value="<?= sanitize($old['province_name'] ?? '') ?>">
        <?php if (isset($errors['province'])): ?>
          <div class="form-error-text"><?= sanitize($errors['province']) ?></div>
        <?php endif; ?>
      </div>

      <!-- Kabupaten / Kota -->
      <div class="form-group">
        <label class="form-label" for="city">Kabupaten / Kota <span class="req">*</span></label>
        <select class="form-control <?= isset($errors['city']) ? 'error' : '' ?>"
                id="city" name="city" required disabled>
          <option value="">— Pilih provinsi dulu —</option>
        </select>
        <input type="hidden" id="city_name" name="city_name"
               value="<?= sanitize($old['city_name'] ?? '') ?>">
        <?php if (isset($errors['city'])): ?>
          <div class="form-error-text"><?= sanitize($errors['city']) ?></div>
        <?php endif; ?>
      </div>

      <!-- TASK 1: Role dropdown -->
      <div class="form-group">
        <label class="form-label" for="role">Role / Jabatan <span class="req">*</span></label>
        <select class="form-control <?= isset($errors['role']) ? 'error' : '' ?>"
                id="role" name="role" required>
          <?php foreach (ALLOWED_ROLES as $r): ?>
            <option value="<?= $r ?>" <?= ($old['role'] ?? 'pasien') === $r ? 'selected' : '' ?>>
              <?= ucfirst($r) ?>
            </option>
          <?php endforeach; ?>
        </select>
        <div class="form-hint">Role dokter/perawat/admin dapat diverifikasi ulang oleh administrator.</div>
        <?php if (isset($errors['role'])): ?>
          <div class="form-error-text"><?= sanitize($errors['role']) ?></div>
        <?php endif; ?>
      </div>

      <!-- Password row -->
      <div class="form-row">
        <div class="form-group">
          <label class="form-label" for="password">Password <span class="req">*</span></label>
          <input class="form-control <?= isset($errors['password']) ? 'error' : '' ?>"
                 type="password" id="password" name="password"
                 placeholder="Min. 6 karakter" required>
          <?php if (isset($errors['password'])): ?>
            <div class="form-error-text"><?= sanitize($errors['password']) ?></div>
          <?php endif; ?>
        </div>
        <div class="form-group">
          <label class="form-label" for="confirm_password">Konfirmasi Password <span class="req">*</span></label>
          <input class="form-control <?= isset($errors['confirm']) ? 'error' : '' ?>"
                 type="password" id="confirm_password" name="confirm_password"
                 placeholder="Ulangi password" required>
          <?php if (isset($errors['confirm'])): ?>
            <div class="form-error-text"><?= sanitize($errors['confirm']) ?></div>
          <?php endif; ?>
        </div>
      </div>

      <button type="submit" class="btn btn-navy btn-lg w-full" style="justify-content:center;margin-top:6px">
        Buat Akun
      </button>
    </form>

    <p style="text-align:center;margin-top:16px;font-size:13px;color:var(--gray-500)">
      Sudah punya akun?
      <a href="<?= BASE_URL ?>/login" style="font-weight:600">Masuk di sini</a>
    </p>
  </div>
</div>

<script src="<?= BASE_URL ?>/public/js/app.js"></script>
<script>
(function () {
  const BPS_KEY  = '4115c372d25a070339527ebbed71cc6a';
  const BASE_API = 'https://webapi.bps.go.id/v1/api';

  const selProv     = document.getElementById('province');
  const selCity     = document.getElementById('city');
  const hidProvName = document.getElementById('province_name');
  const hidCityName = document.getElementById('city_name');

  // Nilai yang disimpan saat POST gagal validasi
  const savedProv = '<?= addslashes($old['province'] ?? '') ?>';
  const savedCity = '<?= addslashes($old['city'] ?? '') ?>';

  // Cache semua data wilayah — hanya fetch SATU kali
  // Struktur: { provinsi: [{id, nama}], kabupaten: { "3200": [{id, nama}], ... } }
  let wilayah = null;

  // ── STEP 1: Fetch semua domain sekaligus dari endpoint /type/all ──────────
  // Endpoint ini mengembalikan SEMUA domain: provinsi + kabupaten dalam satu request.
  // Format domain_id BPS:
  //   - Provinsi  : 4 digit diakhiri "00"  → misal "3200" (Jawa Barat)
  //   - Kabupaten : 4 digit, 2 digit pertama = kode provinsi → misal "3201" (Kab. Bogor)
  async function fetchWilayah() {
    const res  = await fetch(`${BASE_API}/domain/type/all/prov/00000/key/${BPS_KEY}/`);
    const json = await res.json();

    if (json.status !== 'OK' || !Array.isArray(json.data)) {
      throw new Error('Response BPS tidak valid: ' + JSON.stringify(json).slice(0, 120));
    }

    // data[0] = info pagination, data[1] = array semua domain
    const semua = json.data[1] ?? json.data;

    const provinsi   = [];
    const kabupaten  = {}; // key = 2-digit kode provinsi, value = array kabupaten

    semua.forEach(item => {
      const id   = String(item.domain_id);
      const nama = item.domain_name;

      // Provinsi: domain_id 4 karakter diakhiri "00" — misal "3200", "1100"
      if (id.endsWith('00') && id.length === 4) {
        provinsi.push({ id, nama });
      }
      // Kabupaten/Kota: domain_id 4 karakter TIDAK diakhiri "00"
      else if (id.length === 4 && !id.endsWith('00')) {
        const provPrefix = id.substring(0, 2); // 2 digit pertama = kode provinsi
        if (!kabupaten[provPrefix]) kabupaten[provPrefix] = [];
        kabupaten[provPrefix].push({ id, nama });
      }
    });

    // Urutkan nama A–Z
    provinsi.sort((a, b) => a.nama.localeCompare(b.nama, 'id'));
    Object.keys(kabupaten).forEach(k =>
      kabupaten[k].sort((a, b) => a.nama.localeCompare(b.nama, 'id'))
    );

    return { provinsi, kabupaten };
  }

  // ── STEP 2: Isi dropdown provinsi ────────────────────────────────────────
  function isiProvinsi() {
    selProv.innerHTML = '<option value="">— Pilih Provinsi —</option>';
    wilayah.provinsi.forEach(p => {
      const opt        = document.createElement('option');
      opt.value        = p.id;
      opt.textContent  = p.nama;
      opt.dataset.name = p.nama;
      if (p.id === savedProv) opt.selected = true;
      selProv.appendChild(opt);
    });
    selProv.disabled = false;

    // Jika ada provinsi tersimpan (restore setelah POST gagal), langsung isi kabupaten
    if (savedProv) isiKabupaten(savedProv);
  }

  // ── STEP 3: Isi dropdown kabupaten berdasarkan provinsi dipilih ───────────
  // Filter murni client-side — tidak ada fetch tambahan, tidak ada loop
  function isiKabupaten(provId) {
    const provPrefix = String(provId).substring(0, 2);
    const daftar     = wilayah.kabupaten[provPrefix] ?? [];

    selCity.innerHTML = '<option value="">— Pilih Kabupaten/Kota —</option>';

    if (daftar.length === 0) {
      selCity.innerHTML = '<option value="">Tidak ada data untuk provinsi ini</option>';
      selCity.disabled  = true;
      return;
    }

    daftar.forEach(c => {
      const opt        = document.createElement('option');
      opt.value        = c.id;
      opt.textContent  = c.nama;
      opt.dataset.name = c.nama;
      if (c.id === savedCity) opt.selected = true;
      selCity.appendChild(opt);
    });
    selCity.disabled = false;

    // Restore nama kota tersimpan
    if (savedCity) {
      const chosen = selCity.querySelector(`option[value="${savedCity}"]`);
      if (chosen) hidCityName.value = chosen.dataset.name || chosen.textContent;
    }
  }

  // ── Event: ganti provinsi → langsung filter kabupaten (tanpa fetch) ───────
  selProv.addEventListener('change', function () {
    const chosen      = this.options[this.selectedIndex];
    hidProvName.value = chosen.dataset.name || '';
    hidCityName.value = '';
    selCity.innerHTML = '<option value="">— Pilih Kabupaten/Kota —</option>';
    selCity.disabled  = true;

    if (this.value && wilayah) isiKabupaten(this.value);
  });

  selCity.addEventListener('change', function () {
    const chosen      = this.options[this.selectedIndex];
    hidCityName.value = chosen.dataset.name || '';
  });

  // ── Init: fetch sekali, lalu isi provinsi ─────────────────────────────────
  (async () => {
    selProv.disabled  = true;
    selProv.innerHTML = '<option value="">Memuat data wilayah…</option>';
    selCity.disabled  = true;

    try {
      wilayah = await fetchWilayah();
      isiProvinsi();
    } catch (e) {
      selProv.innerHTML = '<option value="">Gagal memuat wilayah — muat ulang halaman</option>';
      selProv.disabled  = false;
      console.error('BPS wilayah error:', e);
    }
  })();
})();
</script>
</body>
</html>