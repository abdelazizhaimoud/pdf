<?php
/**
 * COMPLETE PHP EXAM GUIDE IMPLEMENTATION
 * =====================================
 * This file contains all PHP concepts from the exam preparation guide
 * with detailed comments and practical examples
 * 
 * Table of Contents:
 * 1. PHP Basics & Fundamentals
 * 2. Forms & Input Handling
 * 3. Database Connection & PDO
 * 4. CRUD Operations
 * 5. Authentication System
 * 6. Sessions & Cookies
 * 7. Security Best Practices
 * 8. Shopping Cart Implementation
 * 9. Order Processing System
 * 10. Search & Filter Functionality
 * 11. File Upload & Management
 * 12. Advanced Features
 * 13. Common Patterns & Solutions
 */

// ========================================
// 1. PHP BASICS & FUNDAMENTALS
// ========================================

// Enable error reporting (development only!)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Output methods
echo "Hello World<br>";           // Most common output method
print "Hello<br>";               // Returns 1, less common
// var_dump($variable);          // Shows type and value (debugging)
// print_r($array);             // Human-readable array output

// Variables (always start with $)
$name = "John";                  // String
$age = 25;                       // Integer
$price = 19.99;                  // Float/Double
$is_active = true;               // Boolean
$nothing = null;                 // NULL

// Arrays - Two types
$simple_array = [1, 2, 3];       // Indexed array
$assoc_array = [                 // Associative array (key => value)
    "name" => "John",
    "age" => 25
];

// Constants (cannot be changed once defined)
define("TAX_RATE", 0.10);        // Using define() function
const MAX_SIZE = 100;            // Using const keyword

// String operations
$first_name = "John";
$last_name = "Doe";
$full_name = $first_name . " " . $last_name;  // Concatenation

// Variables in double quotes are parsed
$greeting = "Hello $name";                      // Output: Hello John
$array_value = "Name: {$assoc_array['name']}"; // Complex syntax for arrays

// Variables in single quotes are NOT parsed
$literal = 'Hello $name';                       // Output: Hello $name

// Common string functions
$length = strlen($name);                        // Get string length
$trimmed = trim("  spaces  ");                 // Remove whitespace
$lower = strtolower($name);                    // Convert to lowercase
$upper = strtoupper($name);                    // Convert to uppercase
$replaced = str_replace("John", "Jane", $name); // Replace text

// Control Structures - If/Else
if ($age >= 18) {
    $status = "Adult";
} elseif ($age >= 13) {
    $status = "Teenager";
} else {
    $status = "Child";
}

// Ternary operator (shorthand if-else)
$can_vote = ($age >= 18) ? "Yes" : "No";

// Loops
// For loop
for ($i = 0; $i < 5; $i++) {
    // echo $i . "<br>";
}

// While loop
$count = 0;
while ($count < 3) {
    // echo $count . "<br>";
    $count++;
}

// Foreach loop - VERY IMPORTANT for arrays
foreach ($simple_array as $value) {
    // echo $value . "<br>";
}

// Foreach with key => value
foreach ($assoc_array as $key => $value) {
    // echo "$key: $value<br>";
}

// Switch statement
$action = "create";
switch ($action) {
    case 'create':
        $message = "Creating new record";
        break;
    case 'update':
        $message = "Updating record";
        break;
    case 'delete':
        $message = "Deleting record";
        break;
    default:
        $message = "Unknown action";
        break;
}

// Functions
function calculateTotal($price, $quantity) {
    return $price * $quantity;
}

// Function with default parameter
function greet($name = "Guest") {
    return "Hello, $name!";
}

// Using functions
$total = calculateTotal(19.99, 3);
$greeting1 = greet("John");    // Hello, John!
$greeting2 = greet();           // Hello, Guest!

// ========================================
// 2. DATABASE CONNECTION & PDO
// ========================================

// Database configuration
$db_config = [
    'host' => 'localhost',
    'dbname' => 'php_exam_db',
    'username' => 'root',
    'password' => '',
    'charset' => 'utf8'
];

// Create PDO connection with error handling
try {
    // Create connection string
    $dsn = "mysql:host={$db_config['host']};dbname={$db_config['dbname']};charset={$db_config['charset']}";
    
    // Create PDO instance
    $pdo = new PDO($dsn, $db_config['username'], $db_config['password']);
    
    // Set error mode to throw exceptions
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Set default fetch mode to associative array
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    
    // echo "Database connected successfully!<br>";
    
} catch(PDOException $e) {
    // Handle connection error
    die("Connection failed: " . $e->getMessage());
}

// Database table creation (run once)
$create_tables = false; // Set to true to create tables

if ($create_tables) {
    try {
        // Users table
        $sql = "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            role ENUM('admin', 'customer') DEFAULT 'customer',
            remember_token VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )";
        $pdo->exec($sql);
        
        // Products table
        $sql = "CREATE TABLE IF NOT EXISTS products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description TEXT,
            price DECIMAL(10,2) NOT NULL,
            stock INT DEFAULT 0,
            category VARCHAR(50),
            image_url VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )";
        $pdo->exec($sql);
        
        // Orders table
        $sql = "CREATE TABLE IF NOT EXISTS orders (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            total_amount DECIMAL(10,2) NOT NULL,
            status ENUM('pending', 'processing', 'completed', 'cancelled') DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )";
        $pdo->exec($sql);
        
        // Order items table
        $sql = "CREATE TABLE IF NOT EXISTS order_items (
            id INT AUTO_INCREMENT PRIMARY KEY,
            order_id INT NOT NULL,
            product_id INT NOT NULL,
            quantity INT NOT NULL,
            price DECIMAL(10,2) NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        )";
        $pdo->exec($sql);
        
        // File uploads table
        $sql = "CREATE TABLE IF NOT EXISTS uploads (
            id INT AUTO_INCREMENT PRIMARY KEY,
            original_name VARCHAR(255) NOT NULL,
            file_name VARCHAR(255) NOT NULL,
            file_size INT NOT NULL,
            file_type VARCHAR(50),
            user_id INT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )";
        $pdo->exec($sql);
        
        // Activity log table
        $sql = "CREATE TABLE IF NOT EXISTS activity_log (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            action VARCHAR(100) NOT NULL,
            details TEXT,
            ip_address VARCHAR(45),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )";
        $pdo->exec($sql);
        
        echo "All tables created successfully!<br>";
        
    } catch(PDOException $e) {
        echo "Table creation failed: " . $e->getMessage() . "<br>";
    }
}

// ========================================
// 3. SESSION MANAGEMENT
// ========================================

// MUST be at the very beginning of the file (before any output)
session_start();

// Initialize session variables if needed
if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

// ========================================
// 4. SECURITY HELPER FUNCTIONS
// ========================================

/**
 * Sanitize input data
 * @param string $data Input data to sanitize
 * @return string Sanitized data
 */
function sanitizeInput($data) {
    $data = trim($data);                    // Remove whitespace
    $data = stripslashes($data);            // Remove backslashes
    $data = htmlspecialchars($data);        // Convert special chars
    return $data;
}

/**
 * Generate CSRF token
 * @return string CSRF token
 */
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verify CSRF token
 * @param string $token Token to verify
 * @return bool True if valid, false otherwise
 */
function verifyCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && 
           hash_equals($_SESSION['csrf_token'], $token);
}

// ========================================
// 5. AUTHENTICATION FUNCTIONS
// ========================================

/**
 * Check if user is logged in
 * @return bool True if logged in, false otherwise
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

/**
 * Check if user is admin
 * @return bool True if admin, false otherwise
 */
function isAdmin() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

/**
 * Require login - redirect if not logged in
 */
function requireLogin() {
    if (!isLoggedIn()) {
        header("Location: login.php");
        exit();
    }
}

/**
 * Require admin - redirect if not admin
 */
function requireAdmin() {
    requireLogin();
    if (!isAdmin()) {
        header("Location: dashboard.php");
        exit();
    }
}

/**
 * Login user
 * @param PDO $pdo Database connection
 * @param string $username Username or email
 * @param string $password Plain text password
 * @param bool $remember Remember me option
 * @return array Result with success status and message
 */
function loginUser($pdo, $username, $password, $remember = false) {
    try {
        // Prepare SQL - check both username and email
        $sql = "SELECT id, username, email, password, role FROM users 
                WHERE username = :username OR email = :username";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch();
        
        // Verify user exists and password is correct
        if ($user && password_verify($password, $user['password'])) {
            // Regenerate session ID for security
            session_regenerate_id(true);
            
            // Set session variables
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['email'] = $user['email'];
            $_SESSION['role'] = $user['role'];
            
            // Handle "Remember Me" functionality
            if ($remember) {
                $token = bin2hex(random_bytes(32));
                
                // Store token in database
                $sql = "UPDATE users SET remember_token = :token WHERE id = :id";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([':token' => $token, ':id' => $user['id']]);
                
                // Set cookie for 30 days
                setcookie('remember_token', $token, time() + (30 * 24 * 60 * 60), '/', '', true, true);
            }
            
            // Log activity
            logActivity($pdo, $user['id'], 'login', 'Successful login');
            
            return ['success' => true, 'message' => 'Login successful'];
        } else {
            // Log failed attempt
            if ($user) {
                logActivity($pdo, $user['id'], 'login_failed', 'Failed login attempt');
            }
            return ['success' => false, 'message' => 'Invalid username or password'];
        }
    } catch (PDOException $e) {
        return ['success' => false, 'message' => 'Login failed: ' . $e->getMessage()];
    }
}

/**
 * Register new user
 * @param PDO $pdo Database connection
 * @param array $data User data (username, email, password)
 * @return array Result with success status and message
 */
function registerUser($pdo, $data) {
    $errors = [];
    
    // Validate username
    if (strlen($data['username']) < 3) {
        $errors[] = "Username must be at least 3 characters";
    }
    
    // Validate email
    if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format";
    }
    
    // Validate password
    if (strlen($data['password']) < 6) {
        $errors[] = "Password must be at least 6 characters";
    }
    
    // Check if passwords match
    if ($data['password'] !== $data['confirm_password']) {
        $errors[] = "Passwords do not match";
    }
    
    if (!empty($errors)) {
        return ['success' => false, 'errors' => $errors];
    }
    
    try {
        // Check if username or email already exists
        $sql = "SELECT COUNT(*) FROM users WHERE username = :username OR email = :email";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':username' => $data['username'],
            ':email' => $data['email']
        ]);
        
        if ($stmt->fetchColumn() > 0) {
            return ['success' => false, 'errors' => ['Username or email already exists']];
        }
        
        // Hash password - NEVER store plain text!
        $hashed_password = password_hash($data['password'], PASSWORD_DEFAULT);
        
        // Insert new user
        $sql = "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)";
        $stmt = $pdo->prepare($sql);
        $result = $stmt->execute([
            ':username' => $data['username'],
            ':email' => $data['email'],
            ':password' => $hashed_password
        ]);
        
        if ($result) {
            $user_id = $pdo->lastInsertId();
            logActivity($pdo, $user_id, 'register', 'New user registration');
            return ['success' => true, 'message' => 'Registration successful!'];
        }
        
    } catch (PDOException $e) {
        return ['success' => false, 'errors' => ['Registration failed: ' . $e->getMessage()]];
    }
}

/**
 * Logout user
 */
function logoutUser() {
    // Clear session
    session_start();
    session_destroy();
    
    // Clear remember me cookie
    if (isset($_COOKIE['remember_token'])) {
        setcookie('remember_token', '', time() - 3600, '/');
    }
    
    // Redirect to login
    header("Location: login.php");
    exit();
}

// ========================================
// 6. CRUD OPERATIONS
// ========================================

/**
 * CREATE - Insert new record
 * @param PDO $pdo Database connection
 * @param string $table Table name
 * @param array $data Associative array of column => value
 * @return int|false Last insert ID or false on failure
 */
function create($pdo, $table, $data) {
    try {
        // Build column names and placeholders
        $columns = implode(', ', array_keys($data));
        $placeholders = ':' . implode(', :', array_keys($data));
        
        // Prepare and execute query
        $sql = "INSERT INTO $table ($columns) VALUES ($placeholders)";
        $stmt = $pdo->prepare($sql);
        $result = $stmt->execute($data);
        
        return $result ? $pdo->lastInsertId() : false;
    } catch (PDOException $e) {
        error_log("Create error: " . $e->getMessage());
        return false;
    }
}

/**
 * READ - Get all records
 * @param PDO $pdo Database connection
 * @param string $table Table name
 * @param array $conditions WHERE conditions
 * @param string $order ORDER BY clause
 * @return array Array of records
 */
function readAll($pdo, $table, $conditions = [], $order = '') {
    try {
        $sql = "SELECT * FROM $table";
        $params = [];
        
        // Add WHERE conditions if provided
        if (!empty($conditions)) {
            $where_clauses = [];
            foreach ($conditions as $column => $value) {
                $where_clauses[] = "$column = :$column";
                $params[":$column"] = $value;
            }
            $sql .= " WHERE " . implode(' AND ', $where_clauses);
        }
        
        // Add ORDER BY if provided
        if ($order) {
            $sql .= " ORDER BY $order";
        }
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
        
    } catch (PDOException $e) {
        error_log("Read error: " . $e->getMessage());
        return [];
    }
}

/**
 * READ - Get single record by ID
 * @param PDO $pdo Database connection
 * @param string $table Table name
 * @param int $id Record ID
 * @return array|false Record data or false if not found
 */
function readOne($pdo, $table, $id) {
    try {
        $sql = "SELECT * FROM $table WHERE id = :id";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([':id' => $id]);
        return $stmt->fetch();
    } catch (PDOException $e) {
        error_log("Read one error: " . $e->getMessage());
        return false;
    }
}

/**
 * UPDATE - Update existing record
 * @param PDO $pdo Database connection
 * @param string $table Table name
 * @param array $data Data to update
 * @param int $id Record ID
 * @return bool Success status
 */
function update($pdo, $table, $data, $id) {
    try {
        // Build SET clause
        $set_clauses = [];
        foreach ($data as $column => $value) {
            $set_clauses[] = "$column = :$column";
        }
        
        // Add ID to data array
        $data['id'] = $id;
        
        // Prepare and execute query
        $sql = "UPDATE $table SET " . implode(', ', $set_clauses) . " WHERE id = :id";
        $stmt = $pdo->prepare($sql);
        return $stmt->execute($data);
        
    } catch (PDOException $e) {
        error_log("Update error: " . $e->getMessage());
        return false;
    }
}

/**
 * DELETE - Delete record
 * @param PDO $pdo Database connection
 * @param string $table Table name
 * @param int $id Record ID
 * @return bool Success status
 */
function delete($pdo, $table, $id) {
    try {
        $sql = "DELETE FROM $table WHERE id = :id";
        $stmt = $pdo->prepare($sql);
        return $stmt->execute([':id' => $id]);
    } catch (PDOException $e) {
        error_log("Delete error: " . $e->getMessage());
        return false;
    }
}

// ========================================
// 7. SHOPPING CART FUNCTIONS
// ========================================

/**
 * Add item to cart
 * @param PDO $pdo Database connection
 * @param int $product_id Product ID
 * @param int $quantity Quantity to add
 * @return array Result with success status and message
 */
function addToCart($pdo, $product_id, $quantity = 1) {
    try {
        // Get product details
        $sql = "SELECT id, name, price, stock FROM products WHERE id = :id AND stock > 0";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([':id' => $product_id]);
        $product = $stmt->fetch();
        
        if (!$product) {
            return ['success' => false, 'message' => 'Product not found or out of stock'];
        }
        
        // Check if already in cart
        if (isset($_SESSION['cart'][$product_id])) {
            // Check stock for increased quantity
            $new_quantity = $_SESSION['cart'][$product_id]['quantity'] + $quantity;
            if ($new_quantity > $product['stock']) {
                return ['success' => false, 'message' => 'Not enough stock available'];
            }
            $_SESSION['cart'][$product_id]['quantity'] = $new_quantity;
        } else {
            // Add new item to cart
            if ($quantity > $product['stock']) {
                return ['success' => false, 'message' => 'Not enough stock available'];
            }
            $_SESSION['cart'][$product_id] = [
                'name' => $product['name'],
                'price' => $product['price'],
                'quantity' => $quantity
            ];
        }
        
        return ['success' => true, 'message' => 'Product added to cart'];
        
    } catch (PDOException $e) {
        return ['success' => false, 'message' => 'Error adding to cart'];
    }
}

/**
 * Update cart quantity
 * @param int $product_id Product ID
 * @param int $quantity New quantity
 */
function updateCartQuantity($product_id, $quantity) {
    if ($quantity <= 0) {
        unset($_SESSION['cart'][$product_id]);
    } elseif (isset($_SESSION['cart'][$product_id])) {
        $_SESSION['cart'][$product_id]['quantity'] = $quantity;
    }
}

/**
 * Remove item from cart
 * @param int $product_id Product ID
 */
function removeFromCart($product_id) {
    unset($_SESSION['cart'][$product_id]);
}

/**
 * Get cart total
 * @return float Total amount
 */
function getCartTotal() {
    $total = 0;
    foreach ($_SESSION['cart'] as $item) {
        $total += $item['price'] * $item['quantity'];
    }
    return $total;
}

/**
 * Get cart item count
 * @return int Total number of items
 */
function getCartItemCount() {
    $count = 0;
    foreach ($_SESSION['cart'] as $item) {
        $count += $item['quantity'];
    }
    return $count;
}

/**
 * Clear entire cart
 */
function clearCart() {
    $_SESSION['cart'] = [];
}

// ========================================
// 8. ORDER PROCESSING
// ========================================

/**
 * Process order with transaction
 * @param PDO $pdo Database connection
 * @param int $user_id User ID
 * @return array Result with success status and order ID or error message
 */
function processOrder($pdo, $user_id) {
    // Check if cart is empty
    if (empty($_SESSION['cart'])) {
        return ['success' => false, 'message' => 'Cart is empty'];
    }
    
    try {
        // Start transaction
        $pdo->beginTransaction();
        
        // Calculate totals
        $subtotal = getCartTotal();
        $tax_rate = TAX_RATE; // Using our constant
        $tax = $subtotal * $tax_rate;
        $total = $subtotal + $tax;
        
        // Create order
        $sql = "INSERT INTO orders (user_id, total_amount, status) 
                VALUES (:user_id, :total, 'pending')";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':user_id' => $user_id,
            ':total' => $total
        ]);
        
        $order_id = $pdo->lastInsertId();
        
        // Process each cart item
        foreach ($_SESSION['cart'] as $product_id => $item) {
            // Lock product row and check stock
            $sql = "SELECT stock FROM products WHERE id = :id FOR UPDATE";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([':id' => $product_id]);
            $current_stock = $stmt->fetchColumn();
            
            // Verify sufficient stock
            if ($current_stock < $item['quantity']) {
                throw new Exception("Insufficient stock for {$item['name']}");
            }
            
            // Insert order item
            $sql = "INSERT INTO order_items (order_id, product_id, quantity, price) 
                    VALUES (:order_id, :product_id, :quantity, :price)";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([
                ':order_id' => $order_id,
                ':product_id' => $product_id,
                ':quantity' => $item['quantity'],
                ':price' => $item['price']
            ]);
            
            // Update product stock
            $sql = "UPDATE products SET stock = stock - :quantity WHERE id = :id";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([
                ':quantity' => $item['quantity'],
                ':id' => $product_id
            ]);
        }
        
        // Commit transaction
        $pdo->commit();
        
        // Clear cart after successful order
        clearCart();
        
        // Log activity
        logActivity($pdo, $user_id, 'order_placed', "Order ID: $order_id, Total: $$total");
        
        return ['success' => true, 'order_id' => $order_id, 'total' => $total];
        
    } catch (Exception $e) {
        // Rollback transaction on error
        $pdo->rollback();
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

// ========================================
// 9. SEARCH AND FILTER FUNCTIONS
// ========================================

/**
 * Search products with filters
 * @param PDO $pdo Database connection
 * @param array $filters Search filters
 * @param int $page Page number for pagination
 * @param int $per_page Records per page
 * @return array Search results with pagination info
 */
function searchProducts($pdo, $filters = [], $page = 1, $per_page = 10) {
    try {
        // Base query
        $sql = "SELECT * FROM products WHERE 1=1";
        $count_sql = "SELECT COUNT(*) FROM products WHERE 1=1";
        $params = [];
        
        // Add search term
        if (!empty($filters['search'])) {
            $search_clause = " AND (name LIKE :search OR description LIKE :search)";
            $sql .= $search_clause;
            $count_sql .= $search_clause;
            $params[':search'] = "%{$filters['search']}%";
        }
        
        // Add category filter
        if (!empty($filters['category'])) {
            $category_clause = " AND category = :category";
            $sql .= $category_clause;
            $count_sql .= $category_clause;
            $params[':category'] = $filters['category'];
        }
        
        // Add price range
        if (!empty($filters['min_price'])) {
            $min_price_clause = " AND price >= :min_price";
            $sql .= $min_price_clause;
            $count_sql .= $min_price_clause;
            $params[':min_price'] = $filters['min_price'];
        }
        
        if (!empty($filters['max_price'])) {
            $max_price_clause = " AND price <= :max_price";
            $sql .= $max_price_clause;
            $count_sql .= $max_price_clause;
            $params[':max_price'] = $filters['max_price'];
        }
        
        // Get total count for pagination
        $stmt = $pdo->prepare($count_sql);
        $stmt->execute($params);
        $total_records = $stmt->fetchColumn();
        
        // Calculate pagination
        $total_pages = ceil($total_records / $per_page);
        $offset = ($page - 1) * $per_page;
        
        // Add ORDER BY and LIMIT for pagination
        $sql .= " ORDER BY created_at DESC LIMIT :limit OFFSET :offset";
        
        // Prepare and execute main query
        $stmt = $pdo->prepare($sql);
        foreach ($params as $key => $value) {
            $stmt->bindValue($key, $value);
        }
        $stmt->bindValue(':limit', $per_page, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        
        return [
            'products' => $stmt->fetchAll(),
            'total_records' => $total_records,
            'total_pages' => $total_pages,
            'current_page' => $page,
            'per_page' => $per_page
        ];
        
    } catch (PDOException $e) {
        error_log("Search error: " . $e->getMessage());
        return [
            'products' => [],
            'total_records' => 0,
            'total_pages' => 0,
            'current_page' => 1,
            'per_page' => $per_page
        ];
    }
}

/**
 * Get product categories
 * @param PDO $pdo Database connection
 * @return array List of categories
 */
function getCategories($pdo) {
    try {
        $sql = "SELECT DISTINCT category FROM products 
                WHERE category IS NOT NULL 
                ORDER BY category";
        $stmt = $pdo->query($sql);
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    } catch (PDOException $e) {
        return [];
    }
}

// ========================================
// 10. FILE UPLOAD HANDLING
// ========================================

/**
 * Handle file upload
 * @param array $file Uploaded file array ($_FILES['file'])
 * @param int $user_id ID of the user uploading
 * @param PDO $pdo Database connection
 * @return array Result with success status and message or file info
 */
function handleFileUpload($file, $user_id, $pdo) {
    $upload_dir = 'uploads/';
    $allowed_types = ['image/jpeg', 'image/png', 'application/pdf'];
    $max_size = 5 * 1024 * 1024; // 5MB

    if ($file['error'] !== UPLOAD_ERR_OK) {
        return ['success' => false, 'message' => 'File upload error'];
    }

    if (!in_array($file['type'], $allowed_types)) {
        return ['success' => false, 'message' => 'Invalid file type'];
    }

    if ($file['size'] > $max_size) {
        return ['success' => false, 'message' => 'File too large (max 5MB)'];
    }

    // Generate unique file name
    $ext = pathinfo($file['name'], PATHINFO_EXTENSION);
    $unique_name = uniqid('file_', true) . '.' . $ext;
    $destination = $upload_dir . $unique_name;

    if (!move_uploaded_file($file['tmp_name'], $destination)) {
        return ['success' => false, 'message' => 'Failed to move uploaded file'];
    }

    try {
        // Save file info to DB
        $sql = "INSERT INTO uploads (original_name, file_name, file_size, file_type, user_id)
                VALUES (:original_name, :file_name, :file_size, :file_type, :user_id)";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':original_name' => $file['name'],
            ':file_name' => $unique_name,
            ':file_size' => $file['size'],
            ':file_type' => $file['type'],
            ':user_id' => $user_id
        ]);

        return ['success' => true, 'message' => 'File uploaded successfully', 'file_name' => $unique_name];
    } catch (PDOException $e) {
        return ['success' => false, 'message' => 'Database error: ' . $e->getMessage()];
    }
}
