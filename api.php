<?php
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') exit(0);

$dataFile = __DIR__ . '/data.json';
$authFile = __DIR__ . '/auth.json';

// Инициализация файлов
if (!file_exists($dataFile)) {
    file_put_contents($dataFile, json_encode(['tasks'=>[], 'projects'=>[], 'finances'=>[]], JSON_UNESCAPED_UNICODE));
}
if (!file_exists($authFile)) {
    // 🔑 Данные по умолчанию: логин: admin, пароль: admin123
    $defaultAuth = [
        'users' => [
            ['id'=>1, 'name'=>'Админ', 'password'=>password_hash('admin123', PASSWORD_DEFAULT), 'role'=>'ADMIN']
        ],
        'sessions' => []
    ];
    file_put_contents($authFile, json_encode($defaultAuth, JSON_UNESCAPED_UNICODE));
}

function loadAuth() { return json_decode(file_get_contents($authFile), true); }
function saveAuth($data) { file_put_contents($authFile, json_encode($data, JSON_UNESCAPED_UNICODE)); }

function getCurrentUser() {
    $auth = loadAuth();
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^Bearer (.+)$/', $authHeader, $m)) {
        $token = $m[1];
        $now = time();
        foreach ($auth['sessions'] as $i => $s) {
            if ($s['token'] === $token && strtotime($s['expires']) > $now) {
                foreach ($auth['users'] as $u) {
                    if ($u['id'] === $s['user_id']) return ['id'=>$u['id'], 'name'=>$u['name'], 'role'=>$u['role']];
                }
            } elseif (strtotime($s['expires']) <= $now) {
                unset($auth['sessions'][$i]); // Удаление просроченных
            }
        }
        saveAuth($auth);
    }
    return null;
}

// Маршрутизация
$action = $_GET['action'] ?? $_POST['action'] ?? '';
$raw = file_get_contents('php://input');
$input = json_decode($raw, true) ?: [];

if ($action === 'login') {
    $auth = loadAuth();
    $user = null;
    foreach ($auth['users'] as $u) {
        if ($u['name'] === $input['username'] && password_verify($input['password'], $u['password'])) {
            $user = $u; break;
        }
    }
    if (!$user) { http_response_code(401); echo json_encode(['error'=>'Неверный логин или пароль']); exit; }
    
    $token = bin2hex(random_bytes(32));
    $auth['sessions'][] = ['user_id'=>$user['id'], 'token'=>$token, 'expires'=>date('Y-m-d H:i:s', time()+86400)];
    saveAuth($auth);
    echo json_encode(['token'=>$token, 'user'=>['id'=>$user['id'],'name'=>$user['name'],'role'=>$user['role']]]);
    exit;
}

if ($action === 'logout') {
    $auth = loadAuth();
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/^Bearer (.+)$/', $authHeader, $m)) {
        $auth['sessions'] = array_filter($auth['sessions'], fn($s) => $s['token'] !== $m[1]);
        saveAuth($auth);
    }
    echo json_encode(['status'=>'ok']);
    exit;
}

// Все остальные запросы требуют авторизации
$currentUser = getCurrentUser();
if (!$currentUser) {
    http_response_code(401);
    echo json_encode(['error'=>'Требуется авторизация']);
    exit;
}

// Добавляем инфо о пользователе в ответ GET
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $data = json_decode(file_get_contents($dataFile), true) ?: [];
    $data['_meta'] = ['user' => $currentUser];
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Можно добавить проверку ролей здесь, если нужно
    $fp = fopen($dataFile, 'c');
    if (flock($fp, LOCK_EX)) {
        ftruncate($fp, 0);
        fwrite($fp, json_encode($input, JSON_UNESCAPED_UNICODE));
        flock($fp, LOCK_UN);
    }
    fclose($fp);
    echo json_encode(['status'=>'ok', 'user'=>$currentUser]);
}
?>
