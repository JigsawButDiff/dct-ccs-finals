<?php    
    // All project functions should be placed here

    // Start a new or resume an existing session
    session_start();
    
    /**
     * Retrieves a value from the POST request.
     */
    function postData($key) {
        return $_POST[$key] ?? null;
    }
    
    /**
     * Redirects users to the dashboard if they are already logged in.
     */
    function guardLogin() {
        $dashboardUrl = 'admin/dashboard.php';
        if (!empty($_SESSION['email'])) {
            header("Location: $dashboardUrl");
            exit();
        }
    }


    function guardDashboard(){
        $loginPage = '../index.php';
        if(!isset($_SESSION['email'])){
            header("Location: $loginPage");
        }
    }
    

    
    /**
     * Validates login credentials.
     */
    function validateLoginCredentials($email, $password) {
        $errors = [];
    
        if (empty($email)) {
            $errors[] = "Email is required.";
        } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Invalid email format.";
        }
    
        if (empty($password)) {
            $errors[] = "Password is required.";
        }
    
        return $errors;
    }
    
    /**
     * Handles the login process.
     */
    function login($email, $password) {
        // Validate inputs
        $errors = validateLoginCredentials($email, $password);
        if (!empty($errors)) {
            echo renderErrorMessages($errors);
            return;
        }
    
        // Establish database connection
        $conn = connectToDatabase();
    
        // Hash the password
        $hashedPassword = md5($password);
    
        // Prepare and execute the query
        $sql = "SELECT * FROM users WHERE email = :email AND password = :password";
        $stmt = $conn->prepare($sql);
        $stmt->bindValue(':email', $email);
        $stmt->bindValue(':password', $hashedPassword);
        $stmt->execute();
    
        // Check for matching user
        $user = $stmt->fetch();
    
        if ($user) {
            // Store user session and redirect
            $_SESSION['email'] = $user['email'];
            header("Location: admin/dashboard.php");
            exit();
        } else {
            echo renderErrorMessages(["Invalid email or password."]);
        }
    }
    
    /**
     * Renders error messages as a Bootstrap alert.
     */
    function renderErrorMessages(array $errors) {
        if (empty($errors)) return '';
    
        $output = '<div class="alert alert-danger alert-dismissible fade show" role="alert">';
        $output .= '<strong>Error:</strong><ul>';
    
        foreach ($errors as $error) {
            $output .= '<li>' . htmlspecialchars($error, ENT_QUOTES, 'UTF-8') . '</li>';
        }
    
        $output .= '</ul>';
        $output .= '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>';
        $output .= '</div>';
    
        return $output;
    }
    
    /**
     * Connects to the database and returns a PDO instance.
     */
    function connectToDatabase() {
        $dbConfig = [
            'host'     => 'localhost', // Replace with your host
            'dbname'   => 'dct-ccs-finals', // Replace with your database name
            'user'     => 'root', // Replace with your username
            'password' => '', // Replace with your password
            'charset'  => 'utf8mb4',
        ];
    
        $dsn = "mysql:host={$dbConfig['host']};dbname={$dbConfig['dbname']};charset={$dbConfig['charset']}";
    
        try {
            return new PDO($dsn, $dbConfig['user'], $dbConfig['password'], [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
            ]);
        } catch (PDOException $e) {
            exit("Database connection failed: " . $e->getMessage());
        }
    }
    function displayErrors($errors) {
        if (empty($errors)) return "";
    
        $errorHtml = '<div class="alert alert-danger alert-dismissible fade show" role="alert">';
        $errorHtml .= '<strong>System Alerts</strong><ul>';
    
        foreach ($errors as $error) {
            $errorHtml .= '<li>';
            $errorHtml .= is_array($error) 
                ? implode(", ", $error) 
                : htmlspecialchars($error);
            $errorHtml .= '</li>';
        }
    
        $errorHtml .= '</ul>';
        $errorHtml .= '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>';
        $errorHtml .= '</div>';
    
        return $errorHtml;
    }
   
    function fetchSubjects() {
        global $db; // Ensure you're using the global database connection variable
        if (!$db) {
            die("No Subject Found.");
        }
        $db = new mysqli('localhost', 'username', 'password', 'database_name');

if ($db->connect_error) {
    die("Connection failed: " . $db->connect_error);
}
    
        if (!$db) {
            throw new Exception("Database connection is not initialized.");
        }
    
        $query = "SELECT * FROM subjects";
        $result = $db->query($query);
    
        if (!$result) {
            throw new Exception("Error executing query: " . $db->error);
        }
    
        $subjects = [];
        while ($row = $result->fetch_assoc()) {
            $subjects[] = $row;
        }
    
        return $subjects;
    }
    




// Start session if it's not already started
if (session_status() == PHP_SESSION_NONE) {
    
}

/**
 * Logs the user out by destroying the session and redirecting to a given page.
 */
function GETdata($key){
    return $_GET["$key"];
}


function isPost(){
    return $_SERVER['REQUEST_METHOD'] == "POST";
}


// Assuming you're using mysqli for database connection
function addSubject($subject_code, $subject_name) {
    global $db; // Ensure this is the correct $db object connected to your database
    
    // Prepare the query to insert the new subject into the database
    $stmt = $db->prepare("INSERT INTO subjects (subject_code, subject_name) VALUES (?, ?)");
    $stmt->bind_param("ss", $subject_code, $subject_name); // Bind parameters

    // Execute the query and check if it was successful
    if ($stmt->execute()) {
        echo "Subject added successfully!";
    } else {
        echo "Error adding subject: " . $stmt->error;
    }
    $stmt->close();
}



function logout($indexPage) {
    // Unset the 'email' session variable
    unset($_SESSION['email']);

    // Destroy the session
    session_destroy();

    // Redirect to the login page (index.php)
    header("Location: $indexPage");
    exit;
}





    
?>