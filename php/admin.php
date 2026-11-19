<?php
declare(strict_types=1);
require_once __DIR__ . '/db.php';
session_start();

function h($s): string { return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8'); }

if (!isset($_SESSION['user_id'])) {
    header('Location: ../index.php');
    exit;
}

$local  = file_exists(__DIR__ . '/config.local.php') ? (require __DIR__ . '/config.local.php') : [];
$admins = is_array($local['admins'] ?? null) ? $local['admins'] : [];
if (!in_array($_SESSION['username'] ?? '', $admins, true)) {
    http_response_code(403);
    echo '<!doctype html><meta charset="utf-8"><title>Acces interzis</title>'
       . '<p style="font-family:sans-serif;margin:2rem">Acces interzis. Adaugă numele tău în '
       . '<code>php/config.local.php</code>, la cheia <code>admins</code>.</p>';
    exit;
}

$_SESSION['csrf'] ??= bin2hex(random_bytes(16));

function back(string $tab, string $type, $messages): void
{
    DB::close();
    $_SESSION['flash'] = ['type' => $type, 'msgs' => (array) $messages];
    header('Location: admin.php?tab=' . urlencode($tab));
    exit;
}

function intIn($v, int $min, int $max = 2147483647): ?int
{
    if ($v === null || trim((string) $v) === '') {
        return null;
    }
    $r = filter_var(trim((string) $v), FILTER_VALIDATE_INT, ['options' => ['min_range' => $min, 'max_range' => $max]]);
    return $r === false ? null : (int) $r;
}

function checkUserFields(PDO $pdo, string $username, string $email, ?int $exceptId): array
{
    $e = [];
    if ($username === '') {
        $e[] = 'Username-ul este obligatoriu.';
    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
        $e[] = 'Username-ul trebuie să aibă 3–30 de caractere (litere, cifre sau _).';
    }
    if ($email === '') {
        $e[] = 'Emailul este obligatoriu.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 100) {
        $e[] = 'Adresa de email nu este validă (maximum 100 de caractere).';
    }
    if (!$e) {
        $st = $pdo->prepare('SELECT username, email FROM useri WHERE (username = :u OR email = :e) AND id_user <> :id');
        $st->execute([':u' => $username, ':e' => $email, ':id' => $exceptId ?? 0]);
        foreach ($st->fetchAll() as $row) {
            if (strcasecmp($row['username'], $username) === 0) {
                $e[] = "Username-ul „{$username}” este deja folosit.";
            }
            if (strcasecmp($row['email'], $email) === 0) {
                $e[] = "Emailul „{$email}” este deja înregistrat.";
            }
        }
        $e = array_values(array_unique($e));
    }
    return $e;
}

function handlePost(PDO $pdo): void
{
    if (!hash_equals($_SESSION['csrf'], (string) ($_POST['csrf'] ?? ''))) {
        back('users', 'err', 'Cerere invalidă (token expirat). Încearcă din nou.');
    }
    $action = (string) ($_POST['action'] ?? '');
    $self   = (int) $_SESSION['user_id'];

    if ($action === 'user_create') {
        $username = trim((string) ($_POST['username'] ?? ''));
        $email    = trim((string) ($_POST['email'] ?? ''));
        $pass     = (string) ($_POST['parola'] ?? '');
        $errors   = checkUserFields($pdo, $username, $email, null);
        if ($pass === '') {
            $errors[] = 'Parola este obligatorie.';
        } elseif (strlen($pass) < 8) {
            $errors[] = 'Parola trebuie să aibă cel puțin 8 caractere.';
        }
        if ($errors) back('users', 'err', $errors);

        $st = $pdo->prepare('INSERT INTO useri (username, email, parola_hash, activ) VALUES (:u, :e, :p, :a)');
        $st->execute([':u' => $username, ':e' => $email, ':p' => password_hash($pass, PASSWORD_BCRYPT), ':a' => isset($_POST['activ']) ? 1 : 0]);
        back('users', 'ok', "Utilizatorul „{$username}” a fost adăugat.");
    }

    if ($action === 'user_update') {
        $id       = intIn($_POST['id_user'] ?? null, 1);
        $username = trim((string) ($_POST['username'] ?? ''));
        $email    = trim((string) ($_POST['email'] ?? ''));
        $activ    = isset($_POST['activ']) ? 1 : 0;
        if (!$id) back('users', 'err', 'Utilizator invalid.');
        $exists = $pdo->prepare('SELECT 1 FROM useri WHERE id_user = :id');
        $exists->execute([':id' => $id]);
        if (!$exists->fetchColumn()) back('users', 'err', 'Utilizatorul nu există.');

        $errors = checkUserFields($pdo, $username, $email, $id);
        if ($id === $self && !$activ) $errors[] = 'Nu îți poți dezactiva propriul cont.';
        if ($errors) back('users', 'err', $errors);

        $st = $pdo->prepare('UPDATE useri SET username = :u, email = :e, activ = :a WHERE id_user = :id');
        $st->execute([':u' => $username, ':e' => $email, ':a' => $activ, ':id' => $id]);
        if ($id === $self) $_SESSION['username'] = $username;
        back('users', 'ok', "Utilizatorul „{$username}” a fost modificat.");
    }

    if ($action === 'user_toggle') {
        $id = intIn($_POST['id_user'] ?? null, 1);
        if (!$id) back('users', 'err', 'Utilizator invalid.');
        if ($id === $self) back('users', 'err', 'Nu îți poți dezactiva propriul cont.');
        $st = $pdo->prepare('UPDATE useri SET activ = NOT activ WHERE id_user = :id');
        $st->execute([':id' => $id]);
        back('users', 'ok', 'Starea contului a fost schimbată.');
    }

    if ($action === 'user_delete') {
        $id = intIn($_POST['id_user'] ?? null, 1);
        if (!$id) back('users', 'err', 'Utilizator invalid.');
        if ($id === $self) back('users', 'err', 'Nu îți poți șterge propriul cont.');

        $st = $pdo->prepare('SELECT username FROM useri WHERE id_user = :id');
        $st->execute([':id' => $id]);
        $name = $st->fetchColumn();
        if ($name === false) back('users', 'err', 'Utilizatorul nu există.');

        $c = $pdo->prepare('SELECT (SELECT COUNT(*) FROM quizuri WHERE id_autor = :a) AS q,
                                   (SELECT COUNT(*) FROM rezultate WHERE id_user = :b) AS r');
        $c->execute([':a' => $id, ':b' => $id]);
        $cnt = $c->fetch();
        if ((int) $cnt['q'] > 0 || (int) $cnt['r'] > 0) {
            back('users', 'err', "„{$name}” nu poate fi șters: are {$cnt['q']} quiz-uri și {$cnt['r']} rezultate. Dezactivează contul în loc să îl ștergi.");
        }
        $pdo->prepare('DELETE FROM useri WHERE id_user = :id')->execute([':id' => $id]);
        back('users', 'ok', "Utilizatorul „{$name}” a fost șters.");
    }

    if ($action === 'rezultat_create') {
        $errors = [];
        $idUser = intIn($_POST['id_user'] ?? null, 1);
        $idQuiz = intIn($_POST['id_quiz'] ?? null, 1);
        $user = $quiz = null;

        if (!$idUser) {
            $errors[] = 'Alege un utilizator.';
        } else {
            $st = $pdo->prepare('SELECT username, activ FROM useri WHERE id_user = :id');
            $st->execute([':id' => $idUser]);
            $user = $st->fetch() ?: null;
            if (!$user) $errors[] = 'Utilizatorul ales nu există.';
            elseif (!$user['activ']) $errors[] = 'Utilizatorul ales este dezactivat.';
        }
        if (!$idQuiz) {
            $errors[] = 'Alege un quiz.';
        } else {
            $st = $pdo->prepare('SELECT nr_intrebari, puncte_raspuns FROM quizuri WHERE id_quiz = :id');
            $st->execute([':id' => $idQuiz]);
            $quiz = $st->fetch() ?: null;
            if (!$quiz) $errors[] = 'Quiz-ul ales nu există.';
        }

        $maxCorecte = $quiz ? (int) $quiz['nr_intrebari'] : 100000;
        $corecte = intIn($_POST['raspunsuri_corecte'] ?? null, 0, $maxCorecte);
        if ($corecte === null) {
            $errors[] = "Răspunsurile corecte trebuie să fie un număr întreg între 0 și {$maxCorecte}.";
        }

        $timp = 0;
        if (trim((string) ($_POST['timp_secunde'] ?? '')) !== '') {
            $timp = intIn($_POST['timp_secunde'], 0, 86400);
            if ($timp === null) {
                $errors[] = 'Timpul trebuie să fie un număr întreg de secunde între 0 și 86400.';
                $timp = 0;
            }
        }

        $scor = null;
        if (trim((string) ($_POST['scor'] ?? '')) !== '') {
            $scor = intIn($_POST['scor'], 0, 1000000);
            if ($scor === null) $errors[] = 'Scorul trebuie să fie un număr întreg pozitiv.';
        } elseif ($corecte !== null && $quiz) {
            $scor = $corecte * (int) $quiz['puncte_raspuns'];
        }

        $data = null;
        $raw  = trim((string) ($_POST['data_completarii'] ?? ''));
        if ($raw !== '') {
            $d = DateTime::createFromFormat('Y-m-d\TH:i', $raw);
            if (!$d || $d->format('Y-m-d\TH:i') !== $raw) {
                $errors[] = 'Data are un format invalid (aa-ll-zz hh:mm).';
            } elseif ($d > new DateTime()) {
                $errors[] = 'Data completării nu poate fi în viitor.';
            } else {
                $data = $d->format('Y-m-d H:i:s');
            }
        }

        if ($errors) back('results', 'err', $errors);

        $st = $pdo->prepare('INSERT INTO rezultate (id_user, id_quiz, scor, raspunsuri_corecte, timp_secunde, data_completarii)
                             VALUES (:u, :q, :s, :c, :t, COALESCE(:d, CURRENT_TIMESTAMP))');
        $st->execute([':u' => $idUser, ':q' => $idQuiz, ':s' => $scor, ':c' => $corecte, ':t' => $timp, ':d' => $data]);
        back('results', 'ok', 'Rezultatul a fost adăugat.');
    }

    back('users', 'err', 'Acțiune necunoscută.');
}

$tab   = ($_GET['tab'] ?? 'users') === 'results' ? 'results' : 'users';
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
$fatal = null;
$users = $results = $allUsers = $allQuizzes = [];
$editUser = null;

$uQ     = trim((string) ($_GET['u_q'] ?? ''));
$uActiv = in_array($_GET['u_activ'] ?? '', ['0', '1'], true) ? $_GET['u_activ'] : '';
$uSortC = ['id_user', 'username', 'email', 'data_inregistrarii', 'nr_quizuri', 'nr_rezultate'];
$uSort  = in_array($_GET['u_sort'] ?? '', $uSortC, true) ? $_GET['u_sort'] : 'id_user';
$uDir   = ($_GET['u_dir'] ?? '') === 'desc' ? 'DESC' : 'ASC';

$rUser   = intIn($_GET['r_user'] ?? null, 1);
$rQuiz   = intIn($_GET['r_quiz'] ?? null, 1);
$rMin    = intIn($_GET['r_min'] ?? null, 0, 100);
$rTrecut = in_array($_GET['r_trecut'] ?? '', ['0', '1'], true) ? $_GET['r_trecut'] : '';
$rSortC  = ['data_completarii', 'scor', 'procent', 'username', 'titlu'];
$rSort   = in_array($_GET['r_sort'] ?? '', $rSortC, true) ? $_GET['r_sort'] : 'data_completarii';
$rDir    = ($_GET['r_dir'] ?? 'desc') === 'asc' ? 'ASC' : 'DESC';

try {
    $pdo = DB::get();

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        handlePost($pdo);
    }

    $where = [];
    $p = [];
    if ($uQ !== '') {
        $like = '%' . addcslashes($uQ, '%_\\') . '%';
        $where[] = '(u.username LIKE :q1 OR u.email LIKE :q2)';
        $p[':q1'] = $like;
        $p[':q2'] = $like;
    }
    if ($uActiv !== '') {
        $where[] = 'u.activ = :ac';
        $p[':ac'] = (int) $uActiv;
    }
    $sql = 'SELECT u.id_user, u.username, u.email, u.data_inregistrarii, u.activ,
                   (SELECT COUNT(*) FROM quizuri q WHERE q.id_autor = u.id_user) AS nr_quizuri,
                   (SELECT COUNT(*) FROM rezultate r WHERE r.id_user = u.id_user) AS nr_rezultate
            FROM useri u' . ($where ? ' WHERE ' . implode(' AND ', $where) : '')
         . " ORDER BY {$uSort} {$uDir} LIMIT 200";
    $st = $pdo->prepare($sql);
    $st->execute($p);
    $users = $st->fetchAll();

    $editId = intIn($_GET['edit'] ?? null, 1);
    if ($tab === 'users' && $editId) {
        $st = $pdo->prepare('SELECT id_user, username, email, activ FROM useri WHERE id_user = :id');
        $st->execute([':id' => $editId]);
        $editUser = $st->fetch() ?: null;
    }

    $where = [];
    $p = [];
    if ($rUser)  { $where[] = 'id_user = :ru';  $p[':ru'] = $rUser; }
    if ($rQuiz)  { $where[] = 'id_quiz = :rq';  $p[':rq'] = $rQuiz; }
    if ($rMin !== null) { $where[] = 'procent >= :rm'; $p[':rm'] = $rMin; }
    if ($rTrecut !== '') { $where[] = 'trecut = :rt'; $p[':rt'] = (int) $rTrecut; }
    $sql = 'SELECT * FROM v_rezultate' . ($where ? ' WHERE ' . implode(' AND ', $where) : '')
         . " ORDER BY {$rSort} {$rDir} LIMIT 200";
    $st = $pdo->prepare($sql);
    $st->execute($p);
    $results = $st->fetchAll();

    $allUsers   = $pdo->query('SELECT id_user, username, activ FROM useri ORDER BY username')->fetchAll();
    $allQuizzes = $pdo->query('SELECT id_quiz, titlu, nr_intrebari FROM quizuri ORDER BY titlu')->fetchAll();
} catch (PDOException $e) {
    error_log('[BlitzIQ] admin: ' . $e->getMessage());
    $fatal = 'A apărut o eroare de bază de date. Încearcă din nou.';
} catch (RuntimeException $e) {
    $fatal = $e->getMessage();
} finally {
    DB::close();
}

$csrf = h($_SESSION['csrf']);
?><!doctype html>
<html lang="ro">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BlitzIQ – Administrare</title>
<style>
  :root { --bg:#f5f6fa; --card:#fff; --ink:#1f2330; --muted:#6b7280; --line:#e3e6ee; --brand:#4f6bed; --ok:#16794c; --err:#b3261e; }
  * { box-sizing: border-box; }
  body { margin:0; font:15px/1.5 system-ui, sans-serif; background:var(--bg); color:var(--ink); }
  header { background:var(--card); border-bottom:1px solid var(--line); padding:14px 24px; display:flex; gap:24px; align-items:center; flex-wrap:wrap; }
  header h1 { font-size:18px; margin:0; }
  nav a { padding:6px 12px; border-radius:8px; text-decoration:none; color:var(--muted); }
  nav a.on { background:var(--brand); color:#fff; }
  header .back { margin-left:auto; color:var(--muted); text-decoration:none; }
  main { max-width:1100px; margin:24px auto; padding:0 16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px; margin-bottom:20px; }
  .card h2 { margin:0 0 12px; font-size:16px; }
  form.row { display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end; }
  label { display:flex; flex-direction:column; font-size:13px; color:var(--muted); gap:4px; }
  input, select { font:inherit; padding:7px 10px; border:1px solid var(--line); border-radius:8px; background:#fff; color:var(--ink); }
  label.chk { flex-direction:row; align-items:center; gap:6px; padding-bottom:8px; }
  button { font:inherit; padding:7px 14px; border:0; border-radius:8px; background:var(--brand); color:#fff; cursor:pointer; }
  button.ghost { background:#eef0fb; color:var(--brand); }
  button.danger { background:#fdecea; color:var(--err); }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:9px 8px; border-bottom:1px solid var(--line); font-size:14px; vertical-align:middle; }
  th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  td.act { display:flex; gap:6px; flex-wrap:wrap; }
  td.act form { margin:0; }
  .msg { padding:12px 16px; border-radius:10px; margin-bottom:16px; }
  .msg.ok { background:#e6f4ec; color:var(--ok); }
  .msg.err { background:#fdecea; color:var(--err); }
  .msg ul { margin:0; padding-left:18px; }
  .tag { padding:2px 8px; border-radius:999px; font-size:12px; }
  .tag.on { background:#e6f4ec; color:var(--ok); } .tag.off { background:#f0f0f0; color:var(--muted); }
  .empty { color:var(--muted); padding:16px 0; }
  .wrap { overflow-x:auto; }
</style>
</head>
<body>
<header>
  <h1>BlitzIQ · Administrare</h1>
  <nav>
    <a href="admin.php?tab=users" class="<?= $tab === 'users' ? 'on' : '' ?>">Utilizatori</a>
    <a href="admin.php?tab=results" class="<?= $tab === 'results' ? 'on' : '' ?>">Rezultate</a>
  </nav>
  <a class="back" href="../page.php">← Înapoi la aplicație</a>
</header>
<main>
<?php if ($flash): ?>
  <div class="msg <?= $flash['type'] === 'ok' ? 'ok' : 'err' ?>">
    <?php if (count($flash['msgs']) > 1): ?>
      <ul><?php foreach ($flash['msgs'] as $m): ?><li><?= h($m) ?></li><?php endforeach; ?></ul>
    <?php else: ?><?= h($flash['msgs'][0] ?? '') ?><?php endif; ?>
  </div>
<?php endif; ?>
<?php if ($fatal): ?>
  <div class="msg err"><?= h($fatal) ?></div>
<?php elseif ($tab === 'users'): ?>

  <div class="card">
    <h2><?= $editUser ? 'Modifică utilizatorul #' . (int) $editUser['id_user'] : 'Adaugă utilizator' ?></h2>
    <form class="row" method="post" action="admin.php?tab=users">
      <input type="hidden" name="csrf" value="<?= $csrf ?>">
      <?php if ($editUser): ?>
        <input type="hidden" name="action" value="user_update">
        <input type="hidden" name="id_user" value="<?= (int) $editUser['id_user'] ?>">
      <?php else: ?>
        <input type="hidden" name="action" value="user_create">
      <?php endif; ?>
      <label>Username<input name="username" maxlength="30" value="<?= h($editUser['username'] ?? '') ?>" required></label>
      <label>Email<input name="email" type="text" maxlength="100" value="<?= h($editUser['email'] ?? '') ?>" required></label>
      <?php if (!$editUser): ?>
        <label>Parolă<input name="parola" type="password" autocomplete="new-password" required></label>
      <?php endif; ?>
      <label class="chk"><input type="checkbox" name="activ" value="1" <?= (!$editUser || $editUser['activ']) ? 'checked' : '' ?>> Cont activ</label>
      <button type="submit"><?= $editUser ? 'Salvează' : 'Adaugă' ?></button>
      <?php if ($editUser): ?><a href="admin.php?tab=users"><button type="button" class="ghost">Anulează</button></a><?php endif; ?>
    </form>
  </div>

  <div class="card">
    <h2>Utilizatori (<?= count($users) ?>)</h2>
    <form class="row" method="get" action="admin.php" style="margin-bottom:14px">
      <input type="hidden" name="tab" value="users">
      <label>Căutare (username sau email)<input name="u_q" value="<?= h($uQ) ?>"></label>
      <label>Stare cont
        <select name="u_activ">
          <option value="">Toate</option>
          <option value="1" <?= $uActiv === '1' ? 'selected' : '' ?>>Active</option>
          <option value="0" <?= $uActiv === '0' ? 'selected' : '' ?>>Dezactivate</option>
        </select>
      </label>
      <label>Sortare după
        <select name="u_sort">
          <?php foreach (['id_user' => 'ID', 'username' => 'Username', 'email' => 'Email', 'data_inregistrarii' => 'Data înregistrării', 'nr_quizuri' => 'Nr. quiz-uri', 'nr_rezultate' => 'Nr. rezultate'] as $k => $lbl): ?>
            <option value="<?= $k ?>" <?= $uSort === $k ? 'selected' : '' ?>><?= $lbl ?></option>
          <?php endforeach; ?>
        </select>
      </label>
      <label>Ordine
        <select name="u_dir">
          <option value="asc" <?= $uDir === 'ASC' ? 'selected' : '' ?>>Crescător</option>
          <option value="desc" <?= $uDir === 'DESC' ? 'selected' : '' ?>>Descrescător</option>
        </select>
      </label>
      <button type="submit">Aplică</button>
      <a href="admin.php?tab=users"><button type="button" class="ghost">Resetează</button></a>
    </form>

    <?php if (!$users): ?>
      <p class="empty">Niciun utilizator nu corespunde filtrelor.</p>
    <?php else: ?>
    <div class="wrap"><table>
      <tr><th>ID</th><th>Username</th><th>Email</th><th>Înregistrat</th><th>Stare</th><th>Quiz-uri</th><th>Rezultate</th><th>Acțiuni</th></tr>
      <?php foreach ($users as $u): ?>
      <tr>
        <td><?= (int) $u['id_user'] ?></td>
        <td><?= h($u['username']) ?></td>
        <td><?= h($u['email']) ?></td>
        <td><?= h($u['data_inregistrarii']) ?></td>
        <td><span class="tag <?= $u['activ'] ? 'on' : 'off' ?>"><?= $u['activ'] ? 'activ' : 'dezactivat' ?></span></td>
        <td><?= (int) $u['nr_quizuri'] ?></td>
        <td><?= (int) $u['nr_rezultate'] ?></td>
        <td class="act">
          <a href="admin.php?tab=users&edit=<?= (int) $u['id_user'] ?>"><button type="button" class="ghost">Modifică</button></a>
          <form method="post" action="admin.php?tab=users">
            <input type="hidden" name="csrf" value="<?= $csrf ?>">
            <input type="hidden" name="action" value="user_toggle">
            <input type="hidden" na
