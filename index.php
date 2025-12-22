<?php
session_start();


class Database {
    private $host = "localhost";
    private $username = "root";
    private $password = "";
    private $dbname = "simple_blog";
    public $conn;
    
    public function __construct() {
        $this->conn = new mysqli($this->host, $this->username, $this->password, $this->dbname);
        
        if ($this->conn->connect_error) {
            die("Սխալ կապակցման: " . $this->conn->connect_error);
        }
        
        $this->createTables();
    }
    
    private function createTables() {
        
        $usersTable = "CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )";
        
        
        $categoriesTable = "CREATE TABLE IF NOT EXISTS categories (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )";
        
        
        $newsTable = "CREATE TABLE IF NOT EXISTS news (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(200) NOT NULL,
            content TEXT NOT NULL,
            category_id INT,
            user_id INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (category_id) REFERENCES categories(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )";
        
        $this->conn->query($usersTable);
        $this->conn->query($categoriesTable);
        $this->conn->query($newsTable);
        
    
        $this->initializeCategories();
    }
    
    private function initializeCategories() {
        $categories = ['Աշխարհ', 'Քաղաքականություն', 'Տեխնոլոգիա', 'Սպորտ', 'Գիտություն'];
        
        foreach ($categories as $categoryName) {
            $check = $this->conn->query("SELECT id FROM categories WHERE name = '$categoryName'");
            if ($check->num_rows == 0) {
                $this->conn->query("INSERT INTO categories (name) VALUES ('$categoryName')");
            }
        }
        
        
        $checkNews = $this->conn->query("SELECT COUNT(*) as count FROM news");
        $row = $checkNews->fetch_assoc();
        
        if ($row['count'] == 0) {
            $this->addInitialNews();
        }
    }
    
    private function addInitialNews() {
        $worldCategory = $this->conn->query("SELECT id FROM categories WHERE name = 'Աշխարհ'")->fetch_assoc();
        $worldCategoryId = $worldCategory['id'];
        
        $initialNews = [
            [
                'title' => 'ՄԱԿ-ը դիմում է միջազգային համագործակցությանը',
                'content' => 'Միավորված ազգերի կազմակերպությունը կոչ է անում բոլոր երկրներին աջակցել տնտեսական զարգացման ծրագրերին։ Վերջին տարիներին միջազգային համագործակցությունը դարձել է ավելի կարևոր, քան երբևէ։',
                'category_id' => $worldCategoryId
            ],
            [
                'title' => 'Եվրոպական միությունը ընդունում է նոր միգրացիայի քաղաքականություն',
                'content' => 'Եվրոպական միության անդամ երկրները համաձայնության են եկել նոր միգրացիոն քաղաքականության շուրջ, որը նպատակաուղղված է մարդկանց տեղաշարժի կառավարմանը։',
                'category_id' => $worldCategoryId
            ],
            [
                'title' => 'Ասիայի տնտեսությունները արագ վերականգնվում են համավարակից հետո',
                'content' => 'Տնտեսական վերլուծաբանները նշում են, որ ասիական տնտեսությունները ցուցաբերում են տպավորիչ վերականգնում համաշխարհային համավարակի ազդեցությունից հետո։',
                'category_id' => $worldCategoryId
            ]
        ];
        
        
        $checkUser = $this->conn->query("SELECT id FROM users WHERE username = 'admin'");
        if ($checkUser->num_rows == 0) {
            $hashedPassword = password_hash('admin123', PASSWORD_DEFAULT);
            $this->conn->query("INSERT INTO users (username, password) VALUES ('admin', '$hashedPassword')");
        }
        
        $adminId = $this->conn->query("SELECT id FROM users WHERE username = 'admin'")->fetch_assoc()['id'];
        
        foreach ($initialNews as $news) {
            $stmt = $this->conn->prepare("INSERT INTO news (title, content, category_id, user_id) VALUES (?, ?, ?, ?)");
            $stmt->bind_param("ssii", $news['title'], $news['content'], $news['category_id'], $adminId);
            $stmt->execute();
        }
    }
}


class User {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    public function register($username, $password) {
        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->db->conn->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
        $stmt->bind_param("ss", $username, $hashedPassword);
        
        return $stmt->execute();
    }
    
    public function login($username, $password) {
        $stmt = $this->db->conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($user = $result->fetch_assoc()) {
            if (password_verify($password, $user['password'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                return true;
            }
        }
        return false;
    }
    
    public function logout() {
        session_destroy();
        header("Location: index.php");
        exit();
    }
    
    public function isLoggedIn() {
        return isset($_SESSION['user_id']);
    }
}

// Նորությունների հետ աշխատանքի դաս
class News {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    public function getAllNews() {
        $query = "SELECT n.*, c.name as category_name, u.username 
                  FROM news n 
                  LEFT JOIN categories c ON n.category_id = c.id 
                  LEFT JOIN users u ON n.user_id = u.id 
                  ORDER BY n.created_at DESC";
        return $this->db->conn->query($query);
    }
    
    public function getNewsById($id) {
        $stmt = $this->db->conn->prepare("SELECT n.*, c.name as category_name, u.username 
                  FROM news n 
                  LEFT JOIN categories c ON n.category_id = c.id 
                  LEFT JOIN users u ON n.user_id = u.id 
                  WHERE n.id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        return $stmt->get_result()->fetch_assoc();
    }
    
    public function getNewsByCategory($categoryId) {
        $stmt = $this->db->conn->prepare("SELECT n.*, c.name as category_name, u.username 
                  FROM news n 
                  LEFT JOIN categories c ON n.category_id = c.id 
                  LEFT JOIN users u ON n.user_id = u.id 
                  WHERE n.category_id = ? 
                  ORDER BY n.created_at DESC");
        $stmt->bind_param("i", $categoryId);
        $stmt->execute();
        return $stmt->get_result();
    }
    
    public function addNews($title, $content, $category_id, $user_id) {
        $stmt = $this->db->conn->prepare("INSERT INTO news (title, content, category_id, user_id) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssii", $title, $content, $category_id, $user_id);
        return $stmt->execute();
    }
    
    public function deleteNews($id, $user_id) {
        $stmt = $this->db->conn->prepare("DELETE FROM news WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $id, $user_id);
        return $stmt->execute();
    }
    
    public function getLatestNews($limit = 5) {
        $stmt = $this->db->conn->prepare("SELECT n.*, c.name as category_name, u.username 
                  FROM news n 
                  LEFT JOIN categories c ON n.category_id = c.id 
                  LEFT JOIN users u ON n.user_id = u.id 
                  ORDER BY n.created_at DESC LIMIT ?");
        $stmt->bind_param("i", $limit);
        $stmt->execute();
        return $stmt->get_result();
    }
}

// Կատեգորիաների հետ աշխատանքի դաս
class Category {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    public function getAllCategories() {
        return $this->db->conn->query("SELECT * FROM categories ORDER BY name");
    }
    
    public function getCategoryById($id) {
        $stmt = $this->db->conn->prepare("SELECT * FROM categories WHERE id = ?");
        $stmt->bind_param("i", $id);
        $stmt->execute();
        return $stmt->get_result()->fetch_assoc();
    }
    
    public function getCategoryByName($name) {
        $stmt = $this->db->conn->prepare("SELECT * FROM categories WHERE name = ?");
        $stmt->bind_param("s", $name);
        $stmt->execute();
        return $stmt->get_result()->fetch_assoc();
    }
    
    public function addCategory($name) {
        $stmt = $this->db->conn->prepare("INSERT INTO categories (name) VALUES (?)");
        $stmt->bind_param("s", $name);
        return $stmt->execute();
    }
}


$database = new Database();
$user = new User($database);
$news = new News($database);
$category = new Category($database);


$news_id = isset($_GET['news_id']) ? intval($_GET['news_id']) : 0;
$category_id = isset($_GET['category_id']) ? intval($_GET['category_id']) : 0;

if ($news_id > 0) {
    $singleNews = $news->getNewsById($news_id);
}


if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'register':
                if ($user->register($_POST['username'], $_POST['password'])) {
                    $message = "Գրանցումը հաջողված է! Խնդրում ենք մուտք գործել համակարգ։";
                } else {
                    $error = "Գրանցման սխալ. Հավանաբար օգտատիրոջ անունը զբաղված է։";
                }
                break;
                
            case 'login':
                if ($user->login($_POST['username'], $_POST['password'])) {
                    header("Location: index.php");
                    exit();
                } else {
                    $error = "Սխալ օգտատիրոջ անուն կամ գաղտնաբառ։";
                }
                break;
                
            case 'logout':
                $user->logout();
                break;
                
            case 'add_news':
                if ($user->isLoggedIn() && isset($_POST['title'], $_POST['content'], $_POST['category_id'])) {
                    if ($news->addNews($_POST['title'], $_POST['content'], $_POST['category_id'], $_SESSION['user_id'])) {
                        $message = "Նորությունն հաջողությամբ ավելացվել է։";
                    } else {
                        $error = "Սխալ նորություն ավելացնելիս։";
                    }
                }
                break;
                
            case 'add_category':
                if ($user->isLoggedIn() && isset($_POST['category_name'])) {
                    if ($category->addCategory($_POST['category_name'])) {
                        $message = "Կատեգորիան հաջողությամբ ավելացվել է։";
                    } else {
                        $error = "Սխալ կատեգորիա ավելացնելիս։";
                    }
                }
                break;
                
            case 'delete_news':
                if ($user->isLoggedIn() && isset($_POST['news_id'])) {
                    if ($news->deleteNews($_POST['news_id'], $_SESSION['user_id'])) {
                        $message = "Նորությունը ջնջված է։";
                    } else {
                        $error = "Սխալ նորություն ջնջելիս։";
                    }
                }
                break;
        }
    }
}


$allNews = $news->getAllNews();
$allCategories = $category->getAllCategories();
$isLoggedIn = $user->isLoggedIn();
$currentUsername = $isLoggedIn ? $_SESSION['username'] : '';


if ($category_id > 0) {
    $categoryNews = $news->getNewsByCategory($category_id);
    $currentCategory = $category->getCategoryById($category_id);
}


$latestNews = $news->getLatestNews(4);
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ԱՆՆԱ</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <header>
            <h1>ԱՆՆԱ</h1>
            <nav>
                <ul>
                    <li><a href="index.php">Գլխավոր</a></li>
                    <?php if ($isLoggedIn): ?>
                        <li><a href="#add-news">Ավելացնել նորություն</a></li>
                        <li><a href="#add-category">Ավելացնել կատեգորիա</a></li>
                        <li>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="action" value="logout">
                                <button type="submit" class="btn">Դուրս գալ (<?php echo htmlspecialchars($currentUsername); ?>)</button>
                            </form>
                        </li>
                    <?php else: ?>
                        <li><a href="#login">Մուտք</a></li>
                        <li><a href="#register">Գրանցում</a></li>
                    <?php endif; ?>
                </ul>
            </nav>
        </header>
        
        <?php if (isset($message)): ?>
            <div class="message"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        
        <?php if (isset($error)): ?>
            <div class="error"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        
        <?php if ($isLoggedIn): ?>
            <div class="user-info">
                Դուք մուտք եք գործել որպես՝ <strong><?php echo htmlspecialchars($currentUsername); ?></strong>
            </div>
        <?php endif; ?>
        
        
        <div class="category-filter">
            <a href="index.php">Բոլոր նորությունները</a>
            <?php 
            $categories = $category->getAllCategories(); 
            while ($cat = $categories->fetch_assoc()): 
            ?>
                <a href="index.php?category_id=<?php echo $cat['id']; ?>"><?php echo htmlspecialchars($cat['name']); ?></a>
            <?php endwhile; ?>
        </div>
        
        <?php if ($news_id > 0 && isset($singleNews)): ?>
            
            <div class="news-detail">
                <a href="index.php" class="back-link">← Վերադառնալ նորություններին</a>
                
                <h1 class="news-detail-title"><?php echo htmlspecialchars($singleNews['title']); ?></h1>
                
                <div class="news-meta">
                    <span class="category-badge"><?php echo htmlspecialchars($singleNews['category_name'] ?? 'Առանց կատեգորիայի'); ?></span>
                    <span>Հեղինակ՝ <?php echo htmlspecialchars($singleNews['username']); ?></span>
                    <span> | <?php echo date('d.m.Y H:i', strtotime($singleNews['created_at'])); ?></span>
                </div>
                
                <div class="news-detail-content">
                    <?php echo nl2br(htmlspecialchars($singleNews['content'])); ?>
                </div>
            </div>
            
        <?php elseif ($category_id > 0 && isset($categoryNews)): ?>
           
            <div class="main-content">
                <div>
                    <h2 class="category-title">Կատեգորիա՝ <?php echo htmlspecialchars($currentCategory['name']); ?></h2>
                    
                    <div class="news-grid">
                        <?php if ($categoryNews->num_rows > 0): ?>
                            <?php while ($item = $categoryNews->fetch_assoc()): ?>
                                <div class="news-card">
                                    <div class="news-content">
                                        <h3 class="news-title"><?php echo htmlspecialchars($item['title']); ?></h3>
                                        <div class="news-meta">
                                            <span class="category-badge"><?php echo htmlspecialchars($item['category_name'] ?? 'Առանց կատեգորիայի'); ?></span>
                                            <span>Հեղինակ՝ <?php echo htmlspecialchars($item['username']); ?></span>
                                            <span> | <?php echo date('d.m.Y H:i', strtotime($item['created_at'])); ?></span>
                                        </div>
                                        <div class="news-content">
                                            <?php echo nl2br(htmlspecialchars(substr($item['content'], 0, 200))); ?>
                                            <?php if (strlen($item['content']) > 200): ?>...<?php endif; ?>
                                        </div>
                                        <a href="index.php?news_id=<?php echo $item['id']; ?>" class="btn">Կարդալ ավելին</a>
                                        <?php if ($isLoggedIn && $_SESSION['user_id'] == $item['user_id']): ?>
                                            <form method="POST" onsubmit="return confirm('Ջնջե՞լ այս նորությունը։');" style="margin-top: 10px;">
                                                <input type="hidden" name="action" value="delete_news">
                                                <input type="hidden" name="news_id" value="<?php echo $item['id']; ?>">
                                                <button type="submit" class="btn btn-danger">Ջնջել</button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <p>Այս կատեգորիայում դեռ նորություններ չկան։</p>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="sidebar">
                    <h3>Վերջին նորություններ</h3>
                    <?php while ($latest = $latestNews->fetch_assoc()): ?>
                        <div class="sidebar-news-item">
                            <a href="index.php?news_id=<?php echo $latest['id']; ?>" class="sidebar-news-title"><?php echo htmlspecialchars($latest['title']); ?></a>
                            <small><?php echo date('d.m.Y', strtotime($latest['created_at'])); ?></small>
                        </div>
                    <?php endwhile; ?>
                </div>
            </div>
            
        <?php else: ?>
            
            <div class="main-content">
                <div>
                    <h2>Բոլոր նորությունները</h2>
                    
                    <div class="news-grid">
                        <?php if ($allNews->num_rows > 0): ?>
                            <?php while ($item = $allNews->fetch_assoc()): ?>
                                <div class="news-card">
                                    <div class="news-content">
                                        <h3 class="news-title"><?php echo htmlspecialchars($item['title']); ?></h3>
                                        <div class="news-meta">
                                            <span class="category-badge"><?php echo htmlspecialchars($item['category_name'] ?? 'Առանց կատեգորիայի'); ?></span>
                                            <span>Հեղինակ՝ <?php echo htmlspecialchars($item['username']); ?></span>
                                            <span> | <?php echo date('d.m.Y H:i', strtotime($item['created_at'])); ?></span>
                                        </div>
                                        <div class="news-content">
                                            <?php echo nl2br(htmlspecialchars(substr($item['content'], 0, 200))); ?>
                                            <?php if (strlen($item['content']) > 200): ?>...<?php endif; ?>
                                        </div>
                                        <a href="index.php?news_id=<?php echo $item['id']; ?>" class="btn">Կարդալ ավելին</a>
                                        <?php if ($isLoggedIn && $_SESSION['user_id'] == $item['user_id']): ?>
                                            <form method="POST" onsubmit="return confirm('Ջնջե՞լ այս նորությունը։');" style="margin-top: 10px;">
                                                <input type="hidden" name="action" value="delete_news">
                                                <input type="hidden" name="news_id" value="<?php echo $item['id']; ?>">
                                                <button type="submit" class="btn btn-danger">Ջնջել</button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            <?php endwhile; ?>
                        <?php else: ?>
                            <p>Դեռ նորություններ չկան։ Առաջինը եղեք՝ ով կավելացնի նորություն։</p>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="sidebar">
                    <h3>Վերջին նորություններ</h3>
                    <?php 
                    $latestNews = $news->getLatestNews(4);
                    while ($latest = $latestNews->fetch_assoc()): 
                    ?>
                        <div class="sidebar-news-item">
                            <a href="index.php?news_id=<?php echo $latest['id']; ?>" class="sidebar-news-title"><?php echo htmlspecialchars($latest['title']); ?></a>
                            <small><?php echo date('d.m.Y', strtotime($latest['created_at'])); ?></small>
                        </div>
                    <?php endwhile; ?>
                    
                    <h3 style="margin-top: 30px;">Կատեգորիաներ</h3>
                    <?php 
                    $categories = $category->getAllCategories();
                    while ($cat = $categories->fetch_assoc()): 
                    ?>
                        <div class="sidebar-news-item">
                            <a href="index.php?category_id=<?php echo $cat['id']; ?>" class="sidebar-news-title"><?php echo htmlspecialchars($cat['name']); ?></a>
                        </div>
                    <?php endwhile; ?>
                </div>
            </div>
        <?php endif; ?>
        
       
        <section id="register" class="<?php echo $isLoggedIn ? 'hidden' : ''; ?>">
            <div class="auth-form">
                <h2>Գրանցում</h2>
                <form method="POST">
                    <input type="hidden" name="action" value="register">
                    <div class="form-group">
                        <label for="reg-username">Օգտատիրոջ անուն:</label>
                        <input type="text" id="reg-username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="reg-password">Գաղտնաբառ:</label>
                        <input type="password" id="reg-password" name="password" required>
                    </div>
                    <button type="submit">Գրանցվել</button>
                </form>
            </div>
        </section>
        
        
        <section id="login" class="<?php echo $isLoggedIn ? 'hidden' : ''; ?>">
            <div class="auth-form">
                <h2>Մուտք համակարգ</h2>
                <form method="POST">
                    <input type="hidden" name="action" value="login">
                    <div class="form-group">
                        <label for="login-username">Օգտատիրոջ անուն:</label>
                        <input type="text" id="login-username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="login-password">Գաղտնաբառ:</label>
                        <input type="password" id="login-password" name="password" required>
                    </div>
                    <button type="submit">Մուտք գործել</button>
                </form>
            </div>
        </section>
        
        
        <?php if ($isLoggedIn): ?>
            <section id="add-category">
                <div class="add-form">
                    <h2>Ավելացնել նոր կատեգորիա</h2>
                    <form method="POST">
                        <input type="hidden" name="action" value="add_category">
                        <div class="form-group">
                            <label for="category_name">Կատեգորիայի անվանում:</label>
                            <input type="text" id="category_name" name="category_name" required>
                        </div>
                        <button type="submit">Ավելացնել կատեգորիա</button>
                    </form>
                </div>
            </section>
            
           
            <section id="add-news">
                <div class="add-form">
                    <h2>Ավելացնել նորություն</h2>
                    <form method="POST">
                        <input type="hidden" name="action" value="add_news">
                        <div class="form-group">
                            <label for="title">Վերնագիր:</label>
                            <input type="text" id="title" name="title" required>
                        </div>
                        <div class="form-group">
                            <label for="content">Բովանդակություն:</label>
                            <textarea id="content" name="content" required></textarea>
                        </div>
                        <div class="form-group">
                            <label for="category_id">Կատեգորիա:</label>
                            <select id="category_id" name="category_id" required>
                                <option value="">Ընտրեք կատեգորիա</option>
                                <?php 
                                $categories = $category->getAllCategories();
                                while ($cat = $categories->fetch_assoc()): 
                                ?>
                                    <option value="<?php echo $cat['id']; ?>"><?php echo htmlspecialchars($cat['name']); ?></option>
                                <?php endwhile; ?>
                            </select>
                        </div>
                        <button type="submit">Հրապարակել նորությունը</button>
                    </form>
                </div>
            </section>
        <?php endif; ?>
        
        <footer>
            <p>ԱՆՆԱ &copy; <?php echo date('Y'); ?></p>
            <p>Ընդհանուր նորություններ՝ <?php echo $allNews->num_rows; ?></p>
        </footer>
    </div>
    <script>
         
        document.querySelectorAll('nav a').forEach(link => {
            link.addEventListener('click', function(e) {
                if (this.getAttribute('href').startsWith('#')) {
                    e.preventDefault();
                    const targetId = this.getAttribute('href').substring(1);
                    const targetElement = document.getElementById(targetId);
                    
                    if (targetElement) {
                        
                        document.querySelectorAll('section').forEach(section => {
                            section.classList.remove('active');
                        });
                        
                        
                        targetElement.classList.add('active');
                        
                        
                        targetElement.scrollIntoView({behavior: 'smooth'});
                    }
                }
            });
        });
        
        
        function toggleAuthSections() {
            const isLoggedIn = <?php echo $isLoggedIn ? 'true' : 'false'; ?>;
            
            if (isLoggedIn) {
                document.getElementById('login').classList.add('hidden');
                document.getElementById('register').classList.add('hidden');
                document.getElementById('add-news').classList.remove('hidden');
                document.getElementById('add-category').classList.remove('hidden');
            } else {
                document.getElementById('login').classList.remove('hidden');
                document.getElementById('register').classList.remove('hidden');
                document.getElementById('add-news').classList.add('hidden');
                document.getElementById('add-category').classList.add('hidden');
            }
        }
        
        
        document.addEventListener('DOMContentLoaded', function() {
            toggleAuthSections();
            
            
            const hash = window.location.hash;
            if (hash) {
                const targetElement = document.getElementById(hash.substring(1));
                if (targetElement && targetElement.tagName === 'SECTION') {
                    document.querySelectorAll('section').forEach(section => {
                        section.classList.remove('active');
                    });
                    targetElement.classList.add('active');
                    targetElement.scrollIntoView({behavior: 'smooth'});
                }
            }
        });
        </script>
</body>
</html>
