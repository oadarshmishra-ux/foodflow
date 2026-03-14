<?php
declare(strict_types=1);

// ── CORS HEADERS ────────────────────────────────────────────────────
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit(); }

// ── SERVE STATIC FILES (HTML, CSS, JS) DIRECTLY ─────────────────────
// Without this, the PHP router intercepts everything including .html files
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (preg_match('/\.(html|css|js|png|jpg|gif|ico|svg)$/', $uri)) {
    return false; // Let PHP's built-in server serve the file normally
}
// ────────────────────────────────────────────────────────────────────
/**
 * ============================================================
 *  FoodFlow — Complete REST API Backend (Single File)
 *  Start: php -S localhost:8000 index.php
 *
 *  Sections in this file:
 *   1.  Configuration
 *   2.  Database connection (db.php logic)
 *   3.  Helper utilities   (helpers.php logic)
 *   4.  Users routes       (routes/users.php logic)
 *   5.  Categories routes  (routes/categories.php logic)
 *   6.  Food routes        (routes/food.php logic)
 *   7.  Orders routes      (routes/orders.php logic)
 *   8.  Router / entry point (index.php logic)
 * ============================================================
 */

// ────────────────────────────────────────────────────────────────────


// ============================================================
//  SECTION 1 — CONFIGURATION
// ============================================================

define('DB_HOST',       getenv('DB_HOST')       ?: 'localhost');
define('DB_PORT',       getenv('DB_PORT')       ?: '3306');
define('DB_NAME',       getenv('DB_NAME')       ?: 'foodflow');
define('DB_USER',       getenv('DB_USER')       ?: 'root');
define('DB_PASS',       getenv('DB_PASS')       ?: 'root');         // ← set your MySQL password
define('APP_ENV',       getenv('APP_ENV')       ?: 'development');
define('API_PREFIX',    '/api/v1');
define('TOKEN_SECRET',  getenv('TOKEN_SECRET')  ?: 'ch4nge_me_32+_chars_in_production!');
define('TOKEN_TTL', 2592000); // 30 days
define('BCRYPT_COST',   12);





// ============================================================
//  SECTION 2 — DATABASE CONNECTION  (db.php)
// ============================================================

/**
 * Returns a singleton PDO instance.
 * Opened once per request, reused on subsequent calls.
 * All options configured for maximum safety and performance:
 *   - ERRMODE_EXCEPTION   → DB errors throw, caught by global handler
 *   - FETCH_ASSOC         → rows as plain associative arrays
 *   - EMULATE_PREPARES false → native prepared statements (true SQL safety)
 */
function getDB(): PDO
{
    static $pdo = null;

    if ($pdo !== null) {
        return $pdo;
    }

    $dsn = sprintf(
        'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
        DB_HOST, DB_PORT, DB_NAME
    );

    try {
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
        ]);
    } catch (PDOException $e) {
        http_response_code(503);
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'message' => 'Database unavailable. Please try again later.',
            'detail'  => APP_ENV === 'development' ? $e->getMessage() : null,
        ], JSON_PRETTY_PRINT);
        exit;
    }

    return $pdo;
}

// ============================================================
//  SECTION 3 — HELPER UTILITIES  (helpers.php)
// ============================================================

// ── 3a. JSON response builders ───────────────────────────────

/**
 * Send a successful JSON response and halt.
 *
 * @param mixed  $data     The payload to encode.
 * @param int    $status   HTTP status code.
 * @param string $message  Human-readable success message.
 */
function respond(mixed $data = null, int $status = 200, string $message = 'OK'): never
{
    http_response_code($status);
    header('Content-Type: application/json');

    $body = ['success' => true, 'message' => $message];
    if ($data !== null) {
        $body['data'] = $data;
    }

    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

/**
 * Send an error JSON response and halt.
 *
 * @param string $message  Human-readable error description.
 * @param int    $status   HTTP status code (4xx / 5xx).
 * @param array  $errors   Optional field-level validation errors.
 */
function respondError(string $message, int $status = 400, array $errors = []): never
{
    http_response_code($status);
    header('Content-Type: application/json');

    $body = ['success' => false, 'message' => $message];
    if (!empty($errors)) {
        $body['errors'] = $errors;
    }

    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

// ── 3b. Input helpers ────────────────────────────────────────

/**
 * Decode the raw JSON request body.
 * Returns [] when absent or malformed — never null.
 */
function getBody(): array
{
    $raw = file_get_contents('php://input');
    if (empty($raw)) {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

/**
 * Read a query-string parameter with an optional default.
 */
function getParam(string $key, mixed $default = null): mixed
{
    return $_GET[$key] ?? $default;
}

/**
 * Safely trim a single key from an input array.
 */
function field(array $data, string $key, mixed $default = null): mixed
{
    $val = $data[$key] ?? $default;
    return is_string($val) ? trim($val) : $val;
}

// ── 3c. HMAC token auth ──────────────────────────────────────
//
//  Token format (base64-encoded string):
//      <userId>.<expiry>.<hmac_sha256_signature>
//
//  Signature covers "<userId>.<expiry>" keyed with TOKEN_SECRET.
//  Stateless — no session table needed.

/**
 * Generate a signed Bearer token for the given user ID.
 */
function generateToken(int $userId): string
{
    $expiry  = time() + TOKEN_TTL;
    $payload = "{$userId}.{$expiry}";
    $sig     = hash_hmac('sha256', $payload, TOKEN_SECRET);
    return base64_encode("{$payload}.{$sig}");
}

/**
 * Verify a token and return its decoded payload, or null if invalid/expired.
 *
 * @return array{user_id: int}|null
 */
function verifyToken(string $token): ?array
{
    $raw = base64_decode($token, true);
    if ($raw === false) {
        return null;
    }

    $parts = explode('.', $raw);
    if (count($parts) !== 3) {
        return null;
    }

    [$userId, $expiry, $sig] = $parts;

    // Reject non-numeric segments — prevents type-juggling attacks
    if (!ctype_digit($userId) || !ctype_digit($expiry)) {
        return null;
    }

    // Check expiry
    if ((int)$expiry < time()) {
        return null;
    }

    // Constant-time comparison — prevents timing attacks
    $expected = hash_hmac('sha256', "{$userId}.{$expiry}", TOKEN_SECRET);
    if (!hash_equals($expected, $sig)) {
        return null;
    }

    return ['user_id' => (int)$userId];
}

// ── 3d. Auth middleware ──────────────────────────────────────

/**
 * Verify the Bearer token in the Authorization header.
 * Halts with HTTP 401 if missing or invalid.
 *
 * @return array{user_id: int}
 */
function requireAuth(): array
{
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

    if (!str_starts_with($header, 'Bearer ')) {
        respondError('Authentication required. Send: Authorization: Bearer <token>', 401);
    }

    $payload = verifyToken(substr($header, 7));

    if ($payload === null) {
        respondError('Token is invalid or has expired. Please log in again.', 401);
    }

    return $payload;
}

/**
 * Same as requireAuth() but also verifies the caller is an admin.
 * Halts with HTTP 403 for authenticated non-admin users.
 *
 * @return array{user_id: int}
 */
function requireAdmin(): array
{
    $auth = requireAuth();

    $stmt = getDB()->prepare('SELECT role FROM users WHERE id = ?');
    $stmt->execute([$auth['user_id']]);
    $role = $stmt->fetchColumn();

    if ($role !== 'admin') {
        respondError('Admin privileges are required for this action.', 403);
    }

    return $auth;
}

// ── 3e. Input validation ─────────────────────────────────────

/**
 * Validate an array of fields against a rule-map.
 *
 * Rules (pipe-separated):
 *   required | min:N | max:N | numeric | positive | email | in:a,b,c
 *
 * @param  array $data   Input (e.g. getBody()).
 * @param  array $rules  ['field' => 'rule1|rule2', ...]
 * @return array         Flat list of error strings; empty = valid.
 */
function validate(array $data, array $rules): array
{
    $errors = [];

    foreach ($rules as $field => $ruleString) {
        $value    = $data[$field] ?? null;
        $ruleList = explode('|', $ruleString);
        $label    = ucfirst(str_replace('_', ' ', $field));

        foreach ($ruleList as $rule) {

            // Parametric rules
            if (str_starts_with($rule, 'min:')) {
                $min = (int)substr($rule, 4);
                if ($value !== null && strlen((string)$value) < $min) {
                    $errors[] = "{$label} must be at least {$min} characters.";
                }
                continue;
            }
            if (str_starts_with($rule, 'max:')) {
                $max = (int)substr($rule, 4);
                if ($value !== null && strlen((string)$value) > $max) {
                    $errors[] = "{$label} must not exceed {$max} characters.";
                }
                continue;
            }
            if (str_starts_with($rule, 'in:')) {
                $allowed = explode(',', substr($rule, 3));
                if ($value !== null && !in_array($value, $allowed, true)) {
                    $errors[] = "{$label} must be one of: " . implode(', ', $allowed) . '.';
                }
                continue;
            }

            // Simple rules
            switch ($rule) {
                case 'required':
                    if ($value === null || $value === '') {
                        $errors[] = "{$label} is required.";
                    }
                    break;
                case 'numeric':
                    if ($value !== null && $value !== '' && !is_numeric($value)) {
                        $errors[] = "{$label} must be a number.";
                    }
                    break;
                case 'positive':
                    if ($value !== null && (!is_numeric($value) || (float)$value <= 0)) {
                        $errors[] = "{$label} must be a positive number.";
                    }
                    break;
                case 'email':
                    if ($value !== null && $value !== '' &&
                        !filter_var($value, FILTER_VALIDATE_EMAIL)) {
                        $errors[] = "{$label} must be a valid email address.";
                    }
                    break;
            }
        }
    }

    return $errors;
}

// ============================================================
//  SECTION 4 — USERS ROUTES  (routes/users.php)
//
//  POST   /api/v1/auth/register   Register new account
//  POST   /api/v1/auth/login      Login, receive token
//  GET    /api/v1/users/me        Own profile          [auth]
//  PUT    /api/v1/users/me        Update profile/pw    [auth]
//  GET    /api/v1/users           List all users       [admin]
// ============================================================

/**
 * Dispatcher — called by the router for /auth/* and /users/* paths.
 */
function handleUsers(string $method, array $segments): void
{
    $sub = $segments[1] ?? '';

    if ($segments[0] === 'auth') {
        match ($sub) {
            'register' => $method === 'POST' ? registerUser()
                                             : respondError('Method not allowed.', 405),
            'login'    => $method === 'POST' ? loginUser()
                                             : respondError('Method not allowed.', 405),
            default    => respondError("Unknown auth endpoint: {$sub}.", 404),
        };
        return;
    }

    if ($segments[0] === 'users') {
        if ($sub === 'me') {
            match ($method) {
                'GET' => getOwnProfile(),
                'PUT' => updateOwnProfile(),
                default => respondError('Method not allowed.', 405),
            };
            return;
        }
        if ($sub === '' && $method === 'GET') {
            listAllUsers();
            return;
        }
    }

    respondError('Endpoint not found.', 404);
}

// ── POST /api/v1/auth/register ───────────────────────────────
// Body: { "name":"Alice", "email":"alice@x.com", "password":"pass123",
//         "phone":"9999999999", "address":"123 Main St" }
function registerUser(): void
{
    $body   = getBody();
    $errors = validate($body, [
        'name'     => 'required|min:2|max:120',
        'email'    => 'required|email|max:180',
        'password' => 'required|min:6|max:100',
    ]);

    if ($errors) {
        respondError('Validation failed.', 422, $errors);
    }

    $pdo   = getDB();
    $email = strtolower(field($body, 'email'));

    // Duplicate email check
    $dup = $pdo->prepare('SELECT id FROM users WHERE email = ?');
    $dup->execute([$email]);
    if ($dup->fetchColumn()) {
        respondError('An account with this email already exists.', 409);
    }

    $hash = password_hash(
        field($body, 'password'),
        PASSWORD_BCRYPT,
        ['cost' => BCRYPT_COST]
    );

    $stmt = $pdo->prepare(
        'INSERT INTO users (name, email, password, phone, address)
         VALUES (?, ?, ?, ?, ?)'
    );
    $stmt->execute([
        field($body, 'name'),
        $email,
        $hash,
        field($body, 'phone'),
        field($body, 'address'),
    ]);

    $userId = (int)$pdo->lastInsertId();

    respond([
        'token' => generateToken($userId),
        'user'  => [
            'id'    => $userId,
            'name'  => field($body, 'name'),
            'email' => $email,
            'role'  => 'customer',
        ],
    ], 201, 'Account created successfully. Welcome to FoodFlow!');
}

// ── POST /api/v1/auth/login ──────────────────────────────────
// Body: { "email":"alice@x.com", "password":"pass123" }
function loginUser(): void
{
    $body   = getBody();
    $errors = validate($body, [
        'email'    => 'required|email',
        'password' => 'required',
    ]);

    if ($errors) {
        respondError('Validation failed.', 422, $errors);
    }

    $pdo  = getDB();
    $stmt = $pdo->prepare(
        'SELECT id, name, email, password, role FROM users WHERE email = ?'
    );
    $stmt->execute([strtolower(field($body, 'email'))]);
    $user = $stmt->fetch();

    // Same error for wrong email OR wrong password — prevents user enumeration
    if (!$user || !password_verify(field($body, 'password'), $user['password'])) {
        respondError('Invalid email or password.', 401);
    }

    respond([
        'token' => generateToken((int)$user['id']),
        'user'  => [
            'id'    => (int)$user['id'],
            'name'  => $user['name'],
            'email' => $user['email'],
            'role'  => $user['role'],
        ],
    ], 200, 'Login successful.');
}

// ── GET /api/v1/users/me ─────────────────────────────────────
function getOwnProfile(): void
{
    $auth = requireAuth();
    $pdo  = getDB();

    $stmt = $pdo->prepare(
        'SELECT id, name, email, phone, address, role, created_at
         FROM users WHERE id = ?'
    );
    $stmt->execute([$auth['user_id']]);
    $user = $stmt->fetch();

    if (!$user) {
        respondError('User account not found.', 404);
    }

    $user['id'] = (int)$user['id'];
    respond($user);
}

// ── PUT /api/v1/users/me ─────────────────────────────────────
// Body (all optional): { "name":"...", "phone":"...", "address":"...",
//                        "current_password":"...", "new_password":"..." }
function updateOwnProfile(): void
{
    $auth   = requireAuth();
    $body   = getBody();
    $errors = validate($body, ['name' => 'min:2|max:120']);

    if ($errors) {
        respondError('Validation failed.', 422, $errors);
    }

    $pdo    = getDB();
    $fields = [];
    $params = [];

    foreach (['name', 'phone', 'address'] as $f) {
        if (isset($body[$f])) {
            $fields[] = "{$f} = ?";
            $params[] = field($body, $f);
        }
    }

    // Password change — requires current password
    if (isset($body['new_password'])) {
        if (empty($body['current_password'])) {
            respondError('current_password is required when setting a new password.', 422);
        }
        if (strlen($body['new_password']) < 6) {
            respondError('New password must be at least 6 characters.', 422);
        }
        $pw = $pdo->prepare('SELECT password FROM users WHERE id = ?');
        $pw->execute([$auth['user_id']]);
        if (!password_verify($body['current_password'], $pw->fetchColumn())) {
            respondError('Current password is incorrect.', 403);
        }
        $fields[] = 'password = ?';
        $params[] = password_hash(
            $body['new_password'],
            PASSWORD_BCRYPT,
            ['cost' => BCRYPT_COST]
        );
    }

    if (empty($fields)) {
        respondError('No fields to update were provided.', 400);
    }

    $params[] = $auth['user_id'];
    $pdo->prepare('UPDATE users SET ' . implode(', ', $fields) . ' WHERE id = ?')
        ->execute($params);

    respond(null, 200, 'Profile updated successfully.');
}

// ── GET /api/v1/users  (admin) ───────────────────────────────
// Query params: ?page=1&limit=20
function listAllUsers(): void
{
    requireAdmin();

    $pdo    = getDB();
    $page   = max(1, (int)getParam('page', 1));
    $limit  = min(100, max(1, (int)getParam('limit', 20)));
    $offset = ($page - 1) * $limit;

    $total = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();

    $stmt = $pdo->prepare(
        'SELECT id, name, email, phone, role, created_at
         FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?'
    );
    $stmt->execute([$limit, $offset]);
    $rows = $stmt->fetchAll();

    foreach ($rows as &$row) {
        $row['id'] = (int)$row['id'];
    }

    respond([
        'users'      => $rows,
        'pagination' => [
            'total'       => $total,
            'page'        => $page,
            'per_page'    => $limit,
            'total_pages' => (int)ceil($total / $limit),
        ],
    ]);
}

// ============================================================
//  SECTION 5 — CATEGORIES ROUTES  (routes/categories.php)
//
//  GET    /api/v1/categories        List all   [public]
//  GET    /api/v1/categories/{id}   Get one    [public]
//  POST   /api/v1/categories        Create     [admin]
//  PUT    /api/v1/categories/{id}   Update     [admin]
//  DELETE /api/v1/categories/{id}   Delete     [admin]
// ============================================================

function handleCategories(string $method, array $segments): void
{
    $id = isset($segments[1]) && ctype_digit($segments[1])
        ? (int)$segments[1]
        : null;

    if ($id !== null) {
        match ($method) {
            'GET'    => getCategory($id),
            'PUT'    => updateCategory($id),
            'DELETE' => deleteCategory($id),
            default  => respondError('Method not allowed.', 405),
        };
        return;
    }

    match ($method) {
        'GET'  => listCategories(),
        'POST' => createCategory(),
        default => respondError('Method not allowed.', 405),
    };
}

// ── GET /api/v1/categories ───────────────────────────────────
function listCategories(): void
{
    $rows = getDB()->query(
        'SELECT id, name, description, created_at
         FROM categories ORDER BY name ASC'
    )->fetchAll();

    foreach ($rows as &$row) {
        $row['id'] = (int)$row['id'];
    }

    respond($rows);
}

// ── GET /api/v1/categories/{id} ──────────────────────────────
function getCategory(int $id): void
{
    $pdo  = getDB();
    $stmt = $pdo->prepare(
        'SELECT id, name, description, created_at FROM categories WHERE id = ?'
    );
    $stmt->execute([$id]);
    $cat = $stmt->fetch();

    if (!$cat) {
        respondError("Category #{$id} not found.", 404);
    }

    $cat['id'] = (int)$cat['id'];

    // Bonus: include item count
    $cnt = $pdo->prepare('SELECT COUNT(*) FROM food_items WHERE category_id = ?');
    $cnt->execute([$id]);
    $cat['food_item_count'] = (int)$cnt->fetchColumn();

    respond($cat);
}

// ── POST /api/v1/categories ──────────────────────────────────
// Body: { "name":"Starters", "description":"Small bites" }
function createCategory(): void
{
    requireAdmin();

    $body   = getBody();
    $errors = validate($body, ['name' => 'required|min:2|max:100']);

    if ($errors) {
        respondError('Validation failed.', 422, $errors);
    }

    $pdo = getDB();

    $dup = $pdo->prepare('SELECT id FROM categories WHERE LOWER(name) = LOWER(?)');
    $dup->execute([field($body, 'name')]);
    if ($dup->fetchColumn()) {
        respondError('A category with this name already exists.', 409);
    }

    $stmt = $pdo->prepare('INSERT INTO categories (name, description) VALUES (?, ?)');
    $stmt->execute([field($body, 'name'), field($body, 'description')]);

    respond([
        'id'   => (int)$pdo->lastInsertId(),
        'name' => field($body, 'name'),
    ], 201, 'Category created successfully.');
}

// ── PUT /api/v1/categories/{id} ──────────────────────────────
// Body (partial): { "name":"Mains", "description":"..." }
function updateCategory(int $id): void
{
    requireAdmin();

    $body   = getBody();
    $errors = validate($body, ['name' => 'min:2|max:100']);
    if ($errors) {
        respondError('Validation failed.', 422, $errors);
    }

    $pdo = getDB();

    $e = $pdo->prepare('SELECT id FROM categories WHERE id = ?');
    $e->execute([$id]);
    if (!$e->fetchColumn()) {
        respondError("Category #{$id} not found.", 404);
    }

    $fields = [];
    $params = [];

    if (isset($body['name'])) {
        $fields[] = 'name = ?';
        $params[] = field($body, 'name');
    }
    if (array_key_exists('description', $body)) {
        $fields[] = 'description = ?';
        $params[] = field($body, 'description');
    }

    if (empty($fields)) {
        respondError('No updatable fields provided.', 400);
    }

    $params[] = $id;
    $pdo->prepare('UPDATE categories SET ' . implode(', ', $fields) . ' WHERE id = ?')
        ->execute($params);

    respond(null, 200, 'Category updated successfully.');
}

// ── DELETE /api/v1/categories/{id} ───────────────────────────
function deleteCategory(int $id): void
{
    requireAdmin();

    $pdo = getDB();

    $e = $pdo->prepare('SELECT id FROM categories WHERE id = ?');
    $e->execute([$id]);
    if (!$e->fetchColumn()) {
        respondError("Category #{$id} not found.", 404);
    }

    // Block if food items still reference this category
    $cnt = $pdo->prepare('SELECT COUNT(*) FROM food_items WHERE category_id = ?');
    $cnt->execute([$id]);
    if ((int)$cnt->fetchColumn() > 0) {
        respondError(
            'Cannot delete: this category still has food items. ' .
            'Delete or reassign those items first.',
            409
        );
    }

    $pdo->prepare('DELETE FROM categories WHERE id = ?')->execute([$id]);

    respond(null, 200, 'Category deleted successfully.');
}

// ============================================================
//  SECTION 6 — FOOD ROUTES  (routes/food.php)
//
//  GET    /api/v1/food           List / search    [public]
//  GET    /api/v1/food/{id}      Get one          [public]
//  POST   /api/v1/food           Create           [admin]
//  PUT    /api/v1/food/{id}      Update           [admin]
//  DELETE /api/v1/food/{id}      Delete           [admin]
//
//  Query params for GET /api/v1/food:
//    category_id, search, is_veg, available, page, limit
// ============================================================

function handleFood(string $method, array $segments): void
{
    $id = isset($segments[1]) && ctype_digit($segments[1])
        ? (int)$segments[1]
        : null;

    if ($id !== null) {
        match ($method) {
            'GET'    => getFoodItem($id),
            'PUT'    => updateFoodItem($id),
            'DELETE' => deleteFoodItem($id),
            default  => respondError('Method not allowed.', 405),
        };
        return;
    }

    match ($method) {
        'GET'  => listFoodItems(),
        'POST' => createFoodItem(),
        default => respondError('Method not allowed.', 405),
    };
}

// ── GET /api/v1/food ─────────────────────────────────────────
function listFoodItems(): void
{
    $pdo    = getDB();
    $where  = ['1=1'];
    $params = [];

    // Filter by category
    $catId = getParam('category_id');
    if ($catId !== null && ctype_digit((string)$catId)) {
        $where[]  = 'f.category_id = ?';
        $params[] = (int)$catId;
    }

    // Full-text search on name and description
    $search = getParam('search');
    if ($search !== null && $search !== '') {
        $where[]  = '(f.name LIKE ? OR f.description LIKE ?)';
        $like     = '%' . $search . '%';
        $params[] = $like;
        $params[] = $like;
    }

    // Veg / non-veg filter
    $isVeg = getParam('is_veg');
    if ($isVeg !== null) {
        $where[]  = 'f.is_veg = ?';
        $params[] = $isVeg === '0' ? 0 : 1;
    }

    // Available-only filter (on by default)
    if (getParam('available', '1') === '1') {
        $where[] = 'f.is_available = 1';
    }

    $whereSQL = implode(' AND ', $where);

    // Pagination
    $page   = max(1, (int)getParam('page', 1));
    $limit  = min(100, max(1, (int)getParam('limit', 20)));
    $offset = ($page - 1) * $limit;

    $cntStmt = $pdo->prepare("SELECT COUNT(*) FROM food_items f WHERE {$whereSQL}");
    $cntStmt->execute($params);
    $total = (int)$cntStmt->fetchColumn();

    $sql = "
        SELECT
            f.id, f.name, f.description, f.price,
            f.image_url, f.is_veg, f.is_available, f.created_at,
            c.id   AS category_id,
            c.name AS category_name
        FROM food_items f
        INNER JOIN categories c ON c.id = f.category_id
        WHERE {$whereSQL}
        ORDER BY c.name ASC, f.name ASC
        LIMIT ? OFFSET ?
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute([...$params, $limit, $offset]);
    $rows = $stmt->fetchAll();

    foreach ($rows as &$row) {
        $row['id']           = (int)$row['id'];
        $row['category_id']  = (int)$row['category_id'];
        $row['price']        = (float)$row['price'];
        $row['is_veg']       = (bool)$row['is_veg'];
        $row['is_available'] = (bool)$row['is_available'];
    }

    respond([
        'items'      => $rows,
        'pagination' => [
            'total'       => $total,
            'page'        => $page,
            'per_page'    => $limit,
            'total_pages' => (int)ceil($total / $limit),
        ],
    ]);
}

// ── GET /api/v1/food/{id} ────────────────────────────────────
function getFoodItem(int $id): void
{
    $pdo  = getDB();
    $stmt = $pdo->prepare("
        SELECT f.id, f.name, f.description, f.price,
               f.image_url, f.is_veg, f.is_available, f.created_at,
               c.id AS category_id, c.name AS category_name
        FROM food_items f
        INNER JOIN categories c ON c.id = f.category_id
        WHERE f.id = ?
    ");
    $stmt->execute([$id]);
    $item = $stmt->fetch();

    if (!$item) {
        respondError("Food item #{$id} not found.", 404);
    }

    $item['id']           = (int)$item['id'];
    $item['category_id']  = (int)$item['category_id'];
    $item['price']        = (float)$item['price'];
    $item['is_veg']       = (bool)$item['is_veg'];
    $item['is_available'] = (bool)$item['is_available'];

    respond($item);
}

// ── POST /api/v1/food ────────────────────────────────────────
// Body: { "name":"Paneer Tikka", "description":"...",
//         "category_id":1, "price":220,
//         "image_url":"https://...", "is_veg":true }
function createFoodItem(): void
{
    requireAdmin();

    $body   = getBody();
    $errors = validate($body, [
        'name'        => 'required|min:2|max:180',
        'category_id' => 'required|numeric',
        'price'       => 'required|numeric|positive',
    ]);

    if ($errors) {
        respondError('Validation failed.', 422, $errors);
    }

    $pdo = getDB();

    // Verify referenced category exists
    $catChk = $pdo->prepare('SELECT id FROM categories WHERE id = ?');
    $catChk->execute([(int)$body['category_id']]);
    if (!$catChk->fetchColumn()) {
        respondError("Category #{$body['category_id']} not found.", 404);
    }

    $isVeg = isset($body['is_veg']) ? (int)(bool)$body['is_veg'] : 1;

    $stmt = $pdo->prepare("
        INSERT INTO food_items (name, description, category_id, price, image_url, is_veg)
        VALUES (?, ?, ?, ?, ?, ?)
    ");
    $stmt->execute([
        field($body, 'name'),
        field($body, 'description'),
        (int)$body['category_id'],
        round((float)$body['price'], 2),
        field($body, 'image_url'),
        $isVeg,
    ]);

    respond(['id' => (int)$pdo->lastInsertId()], 201, 'Food item created successfully.');
}

// ── PUT /api/v1/food/{id} ────────────────────────────────────
// Body (partial): { "price":250, "is_available":false }
function updateFoodItem(int $id): void
{
    requireAdmin();

    $body = getBody();
    $pdo  = getDB();

    $e = $pdo->prepare('SELECT id FROM food_items WHERE id = ?');
    $e->execute([$id]);
    if (!$e->fetchColumn()) {
        respondError("Food item #{$id} not found.", 404);
    }

    $fields = [];
    $params = [];

    foreach (['name', 'description', 'image_url'] as $f) {
        if (isset($body[$f])) {
            $fields[] = "{$f} = ?";
            $params[] = field($body, $f);
        }
    }

    if (isset($body['price'])) {
        $errs = validate($body, ['price' => 'numeric|positive']);
        if ($errs) {
            respondError('Validation failed.', 422, $errs);
        }
        $fields[] = 'price = ?';
        $params[] = round((float)$body['price'], 2);
    }

    if (isset($body['category_id'])) {
        $catChk = $pdo->prepare('SELECT id FROM categories WHERE id = ?');
        $catChk->execute([(int)$body['category_id']]);
        if (!$catChk->fetchColumn()) {
            respondError("Category #{$body['category_id']} not found.", 404);
        }
        $fields[] = 'category_id = ?';
        $params[] = (int)$body['category_id'];
    }

    if (isset($body['is_veg'])) {
        $fields[] = 'is_veg = ?';
        $params[] = (int)(bool)$body['is_veg'];
    }
    if (isset($body['is_available'])) {
        $fields[] = 'is_available = ?';
        $params[] = (int)(bool)$body['is_available'];
    }

    if (empty($fields)) {
        respondError('No updatable fields were provided.', 400);
    }

    $params[] = $id;
    $pdo->prepare('UPDATE food_items SET ' . implode(', ', $fields) . ' WHERE id = ?')
        ->execute($params);

    respond(null, 200, 'Food item updated successfully.');
}

// ── DELETE /api/v1/food/{id} ─────────────────────────────────
function deleteFoodItem(int $id): void
{
    requireAdmin();

    $pdo = getDB();

    $e = $pdo->prepare('SELECT id FROM food_items WHERE id = ?');
    $e->execute([$id]);
    if (!$e->fetchColumn()) {
        respondError("Food item #{$id} not found.", 404);
    }

    // Block if item is in any active (non-final) order
    $active = $pdo->prepare("
        SELECT COUNT(*)
        FROM order_items oi
        INNER JOIN orders o ON o.id = oi.order_id
        WHERE oi.food_item_id = ?
          AND o.status NOT IN ('delivered','cancelled')
    ");
    $active->execute([$id]);
    if ((int)$active->fetchColumn() > 0) {
        respondError(
            "Item #{$id} belongs to an active order. " .
            "Mark it unavailable (is_available=false) instead.",
            409
        );
    }

    $pdo->prepare('DELETE FROM food_items WHERE id = ?')->execute([$id]);

    respond(null, 200, 'Food item deleted successfully.');
}

// ============================================================
//  SECTION 7 — ORDERS ROUTES  (routes/orders.php)
//
//  POST   /api/v1/orders                Place order       [auth]
//  GET    /api/v1/orders                List orders       [auth]
//  GET    /api/v1/orders/{id}           Order detail      [auth + owner/admin]
//  PUT    /api/v1/orders/{id}/status    Update status     [admin]
//  DELETE /api/v1/orders/{id}           Cancel order      [auth + owner/admin]
// ============================================================

function handleOrders(string $method, array $segments): void
{
    $rawId = $segments[1] ?? null;
    $sub   = $segments[2] ?? null;

    // /api/v1/orders/{id}/status
    if ($rawId && ctype_digit($rawId) && $sub === 'status' && $method === 'PUT') {
        updateOrderStatus((int)$rawId);
        return;
    }

    // /api/v1/orders/{id}
    if ($rawId && ctype_digit($rawId)) {
        $id = (int)$rawId;
        match ($method) {
            'GET'    => getOrder($id),
            'DELETE' => cancelOrder($id),
            default  => respondError('Method not allowed.', 405),
        };
        return;
    }

    // /api/v1/orders
    match ($method) {
        'GET'  => listOrders(),
        'POST' => placeOrder(),
        default => respondError('Method not allowed.', 405),
    };
}

// ── POST /api/v1/orders ──────────────────────────────────────
// Body: {
//   "items": [
//     { "food_item_id": 1, "quantity": 2 },
//     { "food_item_id": 3, "quantity": 1 }
//   ],
//   "address":        "12 MG Road, Bengaluru",
//   "notes":          "Ring bell twice",
//   "payment_method": "upi"
// }
function placeOrder(): void
{
    $auth   = requireAuth();
    $body   = getBody();
    $errors = validate($body, [
        'address'        => 'required|min:5',
        'payment_method' => 'in:cod,upi,card',
    ]);

    if ($errors) {
        respondError('Validation failed.', 422, $errors);
    }

    $rawItems = $body['items'] ?? [];
    if (!is_array($rawItems) || empty($rawItems)) {
        respondError('Order must include at least one item.', 422);
    }

    $pdo      = getDB();
    $lineItems = [];
    $subtotal  = 0.0;

    // Validate every requested item
    foreach ($rawItems as $index => $item) {
        $fid = $item['food_item_id'] ?? null;
        $qty = (int)($item['quantity'] ?? 1);

        if (!$fid || !ctype_digit((string)$fid)) {
            respondError("items[{$index}].food_item_id must be a positive integer.", 422);
        }
        if ($qty < 1 || $qty > 99) {
            respondError("items[{$index}].quantity must be between 1 and 99.", 422);
        }

        $foodStmt = $pdo->prepare(
            'SELECT id, name, price, is_available FROM food_items WHERE id = ?'
        );
        $foodStmt->execute([(int)$fid]);
        $food = $foodStmt->fetch();

        if (!$food) {
            respondError("Food item #{$fid} not found.", 404);
        }
        if (!(bool)$food['is_available']) {
            respondError("'{$food['name']}' is currently unavailable.", 409);
        }

        $unitPrice  = (float)$food['price'];
        $itemTotal  = round($unitPrice * $qty, 2);
        $subtotal  += $itemTotal;

        $lineItems[] = [
            'food_item_id' => (int)$food['id'],
            'name'         => $food['name'],
            'quantity'     => $qty,
            'unit_price'   => $unitPrice,
            'subtotal'     => $itemTotal,
        ];
    }

    $deliveryFee   = 40.00;
    $tax           = round($subtotal * 0.05, 2);   // 5% GST
    $total         = round($subtotal + $deliveryFee + $tax, 2);
    $paymentMethod = field($body, 'payment_method') ?: 'cod';
    $paymentStatus = $paymentMethod === 'cod' ? 'unpaid' : 'paid';

    // Atomic transaction: order header + line items + status log
    $pdo->beginTransaction();
    try {
        $orderStmt = $pdo->prepare("
            INSERT INTO orders
                (user_id, subtotal, delivery_fee, tax, total,
                 payment_method, payment_status, address, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");
        $orderStmt->execute([
            $auth['user_id'],
            round($subtotal, 2),
            $deliveryFee,
            $tax,
            $total,
            $paymentMethod,
            $paymentStatus,
            field($body, 'address'),
            field($body, 'notes'),
        ]);
        $orderId = (int)$pdo->lastInsertId();

        $lineStmt = $pdo->prepare("
            INSERT INTO order_items
                (order_id, food_item_id, quantity, unit_price, subtotal)
            VALUES (?, ?, ?, ?, ?)
        ");
        foreach ($lineItems as $li) {
            $lineStmt->execute([
                $orderId,
                $li['food_item_id'],
                $li['quantity'],
                $li['unit_price'],
                $li['subtotal'],
            ]);
        }

        $pdo->prepare(
            'INSERT INTO order_status_log (order_id, status) VALUES (?, ?)'
        )->execute([$orderId, 'pending']);

        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        respondError(
            'Failed to place order. Please try again.',
            500,
            APP_ENV === 'development' ? [$e->getMessage()] : []
        );
    }

    respond([
        'order_id'       => $orderId,
        'status'         => 'pending',
        'subtotal'       => round($subtotal, 2),
        'delivery_fee'   => $deliveryFee,
        'tax'            => $tax,
        'total'          => $total,
        'payment_method' => $paymentMethod,
        'payment_status' => $paymentStatus,
        'items'          => $lineItems,
    ], 201, 'Order placed successfully!');
}

// ── GET /api/v1/orders ───────────────────────────────────────
// Customers see their own; admins see all.
// Query params: ?status=pending&page=1&limit=10
function listOrders(): void
{
    $auth = requireAuth();
    $pdo  = getDB();

    $roleStmt = $pdo->prepare('SELECT role FROM users WHERE id = ?');
    $roleStmt->execute([$auth['user_id']]);
    $role = $roleStmt->fetchColumn();

    $where  = ['1=1'];
    $params = [];

    if ($role !== 'admin') {
        $where[]  = 'o.user_id = ?';
        $params[] = $auth['user_id'];
    }

    $validStatuses = [
        'pending','confirmed','preparing',
        'out_for_delivery','delivered','cancelled',
    ];
    $statusFilter = getParam('status');
    if ($statusFilter && in_array($statusFilter, $validStatuses, true)) {
        $where[]  = 'o.status = ?';
        $params[] = $statusFilter;
    }

    $whereSQL = implode(' AND ', $where);
    $page     = max(1, (int)getParam('page', 1));
    $limit    = min(50, max(1, (int)getParam('limit', 10)));
    $offset   = ($page - 1) * $limit;

    $cntStmt = $pdo->prepare("SELECT COUNT(*) FROM orders o WHERE {$whereSQL}");
    $cntStmt->execute($params);
    $total = (int)$cntStmt->fetchColumn();

    $stmt = $pdo->prepare("
        SELECT o.id, o.status, o.subtotal, o.delivery_fee, o.tax, o.total,
               o.payment_method, o.payment_status, o.address, o.notes,
               o.created_at, o.updated_at,
               u.id AS user_id, u.name AS user_name, u.email AS user_email
        FROM orders o
        INNER JOIN users u ON u.id = o.user_id
        WHERE {$whereSQL}
        ORDER BY o.created_at DESC
        LIMIT ? OFFSET ?
    ");
    $stmt->execute([...$params, $limit, $offset]);
    $orders = $stmt->fetchAll();

    foreach ($orders as &$ord) {
        $ord['id']           = (int)$ord['id'];
        $ord['user_id']      = (int)$ord['user_id'];
        $ord['subtotal']     = (float)$ord['subtotal'];
        $ord['delivery_fee'] = (float)$ord['delivery_fee'];
        $ord['tax']          = (float)$ord['tax'];
        $ord['total']        = (float)$ord['total'];
    }

    respond([
        'orders'     => $orders,
        'pagination' => [
            'total'       => $total,
            'page'        => $page,
            'per_page'    => $limit,
            'total_pages' => (int)ceil($total / $limit),
        ],
    ]);
}

// ── GET /api/v1/orders/{id} ──────────────────────────────────
function getOrder(int $id): void
{
    $auth = requireAuth();
    $pdo  = getDB();

    $stmt = $pdo->prepare("
        SELECT o.*, u.name AS user_name, u.email AS user_email
        FROM orders o
        INNER JOIN users u ON u.id = o.user_id
        WHERE o.id = ?
    ");
    $stmt->execute([$id]);
    $order = $stmt->fetch();

    if (!$order) {
        respondError("Order #{$id} not found.", 404);
    }

    $roleStmt = $pdo->prepare('SELECT role FROM users WHERE id = ?');
    $roleStmt->execute([$auth['user_id']]);
    $role = $roleStmt->fetchColumn();

    if ((int)$order['user_id'] !== $auth['user_id'] && $role !== 'admin') {
        respondError('You are not authorised to view this order.', 403);
    }

    // Line items
    $itemStmt = $pdo->prepare("
        SELECT oi.id, oi.food_item_id, oi.quantity, oi.unit_price, oi.subtotal,
               f.name AS food_name, f.image_url AS food_image
        FROM order_items oi
        INNER JOIN food_items f ON f.id = oi.food_item_id
        WHERE oi.order_id = ?
    ");
    $itemStmt->execute([$id]);
    $items = $itemStmt->fetchAll();

    foreach ($items as &$it) {
        $it['id']           = (int)$it['id'];
        $it['food_item_id'] = (int)$it['food_item_id'];
        $it['quantity']     = (int)$it['quantity'];
        $it['unit_price']   = (float)$it['unit_price'];
        $it['subtotal']     = (float)$it['subtotal'];
    }

    // Status audit log
    $logStmt = $pdo->prepare(
        'SELECT status, changed_at FROM order_status_log
         WHERE order_id = ? ORDER BY changed_at ASC'
    );
    $logStmt->execute([$id]);
    $log = $logStmt->fetchAll();

    $order['id']           = (int)$order['id'];
    $order['user_id']      = (int)$order['user_id'];
    $order['subtotal']     = (float)$order['subtotal'];
    $order['delivery_fee'] = (float)$order['delivery_fee'];
    $order['tax']          = (float)$order['tax'];
    $order['total']        = (float)$order['total'];
    $order['items']        = $items;
    $order['status_log']   = $log;

    respond($order);
}

// ── PUT /api/v1/orders/{id}/status  (admin) ──────────────────
// Body: { "status": "confirmed" }
// Valid values: pending|confirmed|preparing|out_for_delivery|delivered|cancelled
function updateOrderStatus(int $id): void
{
    requireAdmin();

    $body   = getBody();
    $errors = validate($body, [
        'status' => 'required|in:pending,confirmed,preparing,out_for_delivery,delivered,cancelled',
    ]);

    if ($errors) {
        respondError('Validation failed.', 422, $errors);
    }

    $pdo  = getDB();
    $stmt = $pdo->prepare('SELECT id, status FROM orders WHERE id = ?');
    $stmt->execute([$id]);
    $order = $stmt->fetch();

    if (!$order) {
        respondError("Order #{$id} not found.", 404);
    }

    if (in_array($order['status'], ['delivered', 'cancelled'], true)) {
        respondError(
            "Order #{$id} is already '{$order['status']}' and cannot be updated.",
            409
        );
    }

    $newStatus = $body['status'];

    $pdo->prepare('UPDATE orders SET status = ? WHERE id = ?')
        ->execute([$newStatus, $id]);

    $pdo->prepare(
        'INSERT INTO order_status_log (order_id, status) VALUES (?, ?)'
    )->execute([$id, $newStatus]);

    respond(['order_id' => $id, 'status' => $newStatus], 200, 'Order status updated.');
}

// ── DELETE /api/v1/orders/{id} ───────────────────────────────
// Customer: can cancel only while status = 'pending'
// Admin:    can cancel any non-final order
function cancelOrder(int $id): void
{
    $auth = requireAuth();
    $pdo  = getDB();

    $stmt = $pdo->prepare('SELECT id, user_id, status FROM orders WHERE id = ?');
    $stmt->execute([$id]);
    $order = $stmt->fetch();

    if (!$order) {
        respondError("Order #{$id} not found.", 404);
    }

    $roleStmt = $pdo->prepare('SELECT role FROM users WHERE id = ?');
    $roleStmt->execute([$auth['user_id']]);
    $role = $roleStmt->fetchColumn();

    $isOwner = (int)$order['user_id'] === $auth['user_id'];
    $isAdmin = $role === 'admin';

    if (!$isOwner && !$isAdmin) {
        respondError('You are not authorised to cancel this order.', 403);
    }

    if (in_array($order['status'], ['delivered', 'cancelled'], true)) {
        respondError(
            "Order #{$id} is already '{$order['status']}' and cannot be cancelled.",
            409
        );
    }

    if ($isOwner && !$isAdmin && $order['status'] !== 'pending') {
        respondError(
            'Orders can only be cancelled before the restaurant confirms them.',
            409
        );
    }

    $pdo->prepare('UPDATE orders SET status = ? WHERE id = ?')
        ->execute(['cancelled', $id]);

    $pdo->prepare(
        'INSERT INTO order_status_log (order_id, status) VALUES (?, ?)'
    )->execute([$id, 'cancelled']);

    respond(null, 200, 'Order cancelled successfully.');
}

// ============================================================
//  SECTION 8 — ROUTER / ENTRY POINT  (index.php logic)
//
//  All requests enter here. The URL is parsed into segments
//  and dispatched to the correct handler function above.
// ============================================================

// ── Global exception handler ─────────────────────────────────
// Catches any unhandled exception and returns clean JSON 500
// instead of an HTML crash page.
set_exception_handler(function (Throwable $e): void {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode([
        'success' => false,
        'message' => 'An unexpected server error occurred.',
        'detail'  => APP_ENV === 'development'
            ? $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine()
            : null,
    ], JSON_PRETTY_PRINT);
    exit;
});

// Convert native PHP errors into exceptions so the handler above catches them
set_error_handler(function (int $errno, string $errstr): bool {
    throw new ErrorException($errstr, 0, $errno);
});

// ── CORS headers ─────────────────────────────────────────────
// Restrict origins in production — replace '*' with your domain.
$allowedOrigins = [
    'http://localhost:3000',
    'http://localhost:5173',  // Vite dev server
    'http://127.0.0.1:5500',  // VS Code Live Server
    'http://localhost:8080',
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowedOrigins, true)) {
    header("Access-Control-Allow-Origin: {$origin}");
    header('Vary: Origin');
} else {
    header('Access-Control-Allow-Origin: *');
}
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Max-Age: 86400');
header('Content-Type: application/json; charset=UTF-8');

// Handle preflight (OPTIONS) requests immediately
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// ── Parse request ─────────────────────────────────────────────
$method  = strtoupper($_SERVER['REQUEST_METHOD']);
$rawPath = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

// Reject requests that don't begin with our API prefix
if (!str_starts_with($rawPath, API_PREFIX)) {
    http_response_code(404);
    echo json_encode([
        'success' => false,
        'message' => 'Not found. All endpoints start with ' . API_PREFIX . '/',
    ], JSON_PRETTY_PRINT);
    exit;
}

// Strip prefix: "/api/v1/food/3" → "food/3" → ['food', '3']
$path     = ltrim(substr($rawPath, strlen(API_PREFIX)), '/');
$segments = $path !== '' ? explode('/', $path) : [];

// ── Health-check at /api/v1 ───────────────────────────────────
if (empty($segments)) {
    respond([
        'name'      => 'FoodFlow REST API',
        'version'   => 'v1',
        'status'    => 'operational',
        'timestamp' => date('Y-m-d\TH:i:s\Z'),
        'endpoints' => [
            'register'   => 'POST   ' . API_PREFIX . '/auth/register',
            'login'      => 'POST   ' . API_PREFIX . '/auth/login',
            'profile'    => 'GET    ' . API_PREFIX . '/users/me',
            'categories' => 'GET    ' . API_PREFIX . '/categories',
            'food'       => 'GET    ' . API_PREFIX . '/food',
            'orders'     => 'POST   ' . API_PREFIX . '/orders',
        ],
    ], 200, 'Welcome to FoodFlow API');
}

// ── Dispatch to the right handler ────────────────────────────
$resource = $segments[0];

match (true) {
    $resource === 'auth'       => handleUsers($method, $segments),
    $resource === 'users'      => handleUsers($method, $segments),
    $resource === 'categories' => handleCategories($method, $segments),
    $resource === 'food'       => handleFood($method, $segments),
    $resource === 'orders'     => handleOrders($method, $segments),
    default                    => respondError(
        "Unknown resource '{$resource}'. " .
        "Available: auth, users, categories, food, orders.",
        404
    ),
};