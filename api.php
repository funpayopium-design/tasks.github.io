<?php
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') exit(0);

session_start();

$dataFile = __DIR__ . '/data.json';
$authFile = __DIR__ . '/auth.json';

// Инициализация файлов
if (!file_exists($dataFile)) {
    file_put_contents($dataFile, json_encode([
        'tasks' => [],
        'projects' => [],
        'finances' => [],
        'users' => []
    ], JSON_UNESCAPED_UNICODE));
}

if (!file_exists($authFile)) {
    file_put_contents($authFile, json_encode([
        'users' => [
            [
                'id' => 1,
                'name' => 'Администратор',
                'username' => 'admin',
                'password' => password_hash('admin123', PASSWORD_DEFAULT),
                'role' => 'ADMIN',
                'created_at' => date('Y-m-d H:i:s'),
                'last_activity' => date('Y-m-d H:i:s')
            ]
        ],
        'sessions' => []
    ], JSON_UNESCAPED_UNICODE));
}

function loadAuth() { 
    return json_decode(file_get_contents(__DIR__ . '/auth.json'), true); 
}

function saveAuth($data) { 
    file_put_contents(__DIR__ . '/auth.json', json_encode($data, JSON_UNESCAPED_UNICODE)); 
}

function loadData() { 
    return json_decode(file_get_contents(__DIR__ . '/data.json'), true); 
}

function saveData($data) { 
    file_put_contents(__DIR__ . '/data.json', json_encode($data, JSON_UNESCAPED_UNICODE)); 
}

function getCurrentUser() {
    $auth = loadAuth();
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    
    if (preg_match('/^Bearer (.+)$/', $authHeader, $m)) {
        $token = $m[1];
        $now = time();
        $currentTime = date('Y-m-d H:i:s');
        
        foreach ($auth['sessions'] as $i => $s) {
            $sessionTime = strtotime($s['last_activity']);
            $isExpired = ($now - $sessionTime) > 1800; // 30 минут
            
            if ($s['token'] === $token && !$isExpired) {
                // Обновляем last_activity
                $auth['sessions'][$i]['last_activity'] = $currentTime;
                saveAuth($auth);
                
                foreach ($auth['users'] as $u) {
                    if ($u['id'] === $s['user_id']) {
                        // Обновляем last_activity пользователя
                        foreach ($auth['users'] as &$user) {
                            if ($user['id'] === $u['id']) {
                                $user['last_activity'] = $currentTime;
                                break;
                            }
                        }
                        saveAuth($auth);
                        return ['id'=>$u['id'], 'name'=>$u['name'], 'username'=>$u['username'], 'role'=>$u['role']];
                    }
                }
            } elseif ($isExpired) {
                unset($auth['sessions'][$i]);
            }
        }
        saveAuth($auth);
    }
    return null;
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';
$raw = file_get_contents('php://input');
$input = json_decode($raw, true) ?: [];

// Регистрация
if ($action === 'register') {
    $auth = loadAuth();
    
    // Проверка существования username
    foreach ($auth['users'] as $u) {
        if ($u['username'] === $input['username']) {
            http_response_code(409);
            echo json_encode(['error' => 'Пользователь уже существует']);
            exit;
        }
    }
    
    $newUser = [
        'id' => count($auth['users']) + 1,
        'name' => $input['name'],
        'username' => $input['username'],
        'password' => password_hash($input['password'], PASSWORD_DEFAULT),
        'role' => 'USER',
        'created_at' => date('Y-m-d H:i:s'),
        'last_activity' => date('Y-m-d H:i:s')
    ];
    
    $auth['users'][] = $newUser;
    saveAuth($auth);
    
    $token = bin2hex(random_bytes(32));
    $auth['sessions'][] = [
        'user_id' => $newUser['id'],
        'token' => $token,
        'created' => date('Y-m-d H:i:s'),
        'last_activity' => date('Y-m-d H:i:s')
    ];
    saveAuth($auth);
    
    echo json_encode([
        'token' => $token,
        'user' => [
            'id' => $newUser['id'],
            'name' => $newUser['name'],
            'username' => $newUser['username'],
            'role' => $newUser['role']
        ]
    ]);
    exit;
}

// Вход
if ($action === 'login') {
    $auth = loadAuth();
    $user = null;
    
    foreach ($auth['users'] as $u) {
        if (($u['username'] === $input['username'] || $u['name'] === $input['username']) 
            && password_verify($input['password'], $u['password'])) {
            $user = $u;
            break;
        }
    }
    
    if (!$user) {
        http_response_code(401);
        echo json_encode(['error' => 'Неверный логин или пароль']);
        exit;
    }
    
    $token = bin2hex(random_bytes(32));
    $auth['sessions'][] = [
        'user_id' => $user['id'],
        'token' => $token,
        'created' => date('Y-m-d H:i:s'),
        'last_activity' => date('Y-m-d H:i:s')
    ];
    saveAuth($auth);
    
    echo json_encode([
        'token' => $token,
        'user' => [
            'id' => $user['id'],
            'name' => $user['name'],
            'username' => $user['username'],
            'role' => $user['role']
        ]
    ]);
    exit;
}

// Выход
if ($action === 'logout') {
    $auth = loadAuth();
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    
    if (preg_match('/^Bearer (.+)$/', $authHeader, $m)) {
        $auth['sessions'] = array_filter($auth['sessions'], fn($s) => $s['token'] !== $m[1]);
        saveAuth($auth);
    }
    
    echo json_encode(['status' => 'ok']);
    exit;
}

// Получение списка пользователей (только ADMIN)
if ($action === 'getUsers') {
    $currentUser = getCurrentUser();
    if (!$currentUser || $currentUser['role'] !== 'ADMIN') {
        http_response_code(403);
        echo json_encode(['error' => 'Доступ запрещен']);
        exit;
    }
    
    $auth = loadAuth();
    $now = time();
    
    $usersWithStatus = array_map(function($u) use ($now) {
        $lastActivity = strtotime($u['last_activity']);
        $isOnline = ($now - $lastActivity) < 300; // Онлайн если был активен последние 5 минут
        
        return [
            'id' => $u['id'],
            'name' => $u['name'],
            'username' => $u['username'],
            'role' => $u['role'],
            'created_at' => $u['created_at'],
            'last_activity' => $u['last_activity'],
            'is_online' => $isOnline
        ];
    }, $auth['users']);
    
    echo json_encode(['users' => $usersWithStatus]);
    exit;
}

// Изменение роли пользователя (только ADMIN)
if ($action === 'changeRole') {
    $currentUser = getCurrentUser();
    if (!$currentUser || $currentUser['role'] !== 'ADMIN') {
        http_response_code(403);
        echo json_encode(['error' => 'Доступ запрещен']);
        exit;
    }
    
    $auth = loadAuth();
    $targetId = $input['user_id'];
    $newRole = $input['role'];
    
    foreach ($auth['users'] as &$user) {
        if ($user['id'] == $targetId) {
            $user['role'] = $newRole;
            break;
        }
    }
    saveAuth($auth);
    
    echo json_encode(['status' => 'ok']);
    exit;
}

// Удаление пользователя (только ADMIN)
if ($action === 'deleteUser') {
    $currentUser = getCurrentUser();
    if (!$currentUser || $currentUser['role'] !== 'ADMIN') {
        http_response_code(403);
        echo json_encode(['error' => 'Доступ запрещен']);
        exit;
    }
    
    $auth = loadAuth();
    $targetId = $input['user_id'];
    
    // Нельзя удалить себя
    if ($targetId == $currentUser['id']) {
        http_response_code(400);
        echo json_encode(['error' => 'Нельзя удалить себя']);
        exit;
    }
    
    $auth['users'] = array_filter($auth['users'], fn($u) => $u['id'] != $targetId);
    $auth['users'] = array_values($auth['users']);
    
    // Удаляем сессии этого пользователя
    $auth['sessions'] = array_filter($auth['sessions'], fn($s) => $s['user_id'] != $targetId);
    
    saveAuth($auth);
    echo json_encode(['status' => 'ok']);
    exit;
}

// Все остальные запросы требуют авторизации
$currentUser = getCurrentUser();
if (!$currentUser) {
    http_response_code(401);
    echo json_encode(['error' => 'Требуется авторизация']);
    exit;
}

// GET - получение данных
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $data = loadData();
    $data['_meta'] = ['user' => $currentUser];
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    saveData($input);
    echo json_encode(['status' => 'ok', 'user' => $currentUser]);
}
?>
