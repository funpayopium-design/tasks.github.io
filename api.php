<?php
header('Content-Type: application/json; charset=utf-8');
$file = __DIR__ . '/data.json';
$default = json_encode([
    'tasks' => [],
    'projects' => [],
    'finances' => [],
    'users' => [
        ['name' => 'Администратор', 'role' => 'ADMIN'],
        ['name' => 'Менеджер', 'role' => 'USER']
    ]
], JSON_UNESCAPED_UNICODE);

if (!file_exists($file)) {
    file_put_contents($file, $default);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    echo file_get_contents($file);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    if ($data) {
        $fp = fopen($file, 'c');
        if (flock($fp, LOCK_EX)) {
            ftruncate($fp, 0);
            fwrite($fp, json_encode($data, JSON_UNESCAPED_UNICODE));
            flock($fp, LOCK_UN);
        }
        fclose($fp);
        echo json_encode(['status' => 'ok']);
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid JSON']);
    }
    exit;
}

http_response_code(405);
echo json_encode(['error' => 'Method not allowed']);
?>
