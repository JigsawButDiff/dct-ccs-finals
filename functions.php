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
    // Get the database connection
    $conn = connectToDatabase();

    try {
        // Prepare SQL query to fetch all subjects
        $sql = "SELECT * FROM subjects";
        $stmt = $conn->prepare($sql);

        // Execute the query
        $stmt->execute();

        // Fetch all subjects as an associative array
        $subjects = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Return the list of subjects
        return $subjects;
    } catch (PDOException $e) {
        // Return an empty array in case of error
        return [];
    }
}
    

function addSubject($subject_code, $subject_name) {
    // Validate subject data
    $validateSubjectData = validateSubjectData($subject_code, $subject_name);

    // Check for duplicate subject data
    $checkDuplicate = checkDuplicateSubjectData($subject_code, $subject_name);

    // Handle validation errors
    if (count($validateSubjectData) > 0) {
        echo displayErrors($validateSubjectData);
        return;
    }

    // Handle duplicate data errors
    if (count($checkDuplicate) == 1) {
        echo displayErrors($checkDuplicate);
        return;
    }

    // Get database connection
    $conn = connectToDatabase();

    try {
        // Prepare SQL query to insert subject into the database
        $sql = "INSERT INTO subjects (subject_code, subject_name) VALUES (:subject_code, :subject_name)";
        $stmt = $conn->prepare($sql);

        // Bind parameters to the SQL query
        $stmt->bindParam(':subject_code', $subject_code);
        $stmt->bindParam(':subject_name', $subject_name);

        // Execute the query and handle the result
        if ($stmt->execute()) {
            return true; // Subject successfully added
        } else {
            return "Failed to add subject."; // Query execution failed
        }
    } catch (PDOException $e) {
        // Log and return error message if the query fails
        error_log("Database error: " . $e->getMessage()); // Log the error for debugging
        return "Error: " . $e->getMessage();
    }
}

    function validateSubjectData($subject_code, $subject_name ) {
        $errors = [];
    
        // Check if subject_code is empty
        if (empty($subject_code)) {
            $errors[] = "Subject code is required.";
        }
    
        // Check if subject_name is empty
        if (empty($subject_name)) {
            $errors[] = "Subject name is required.";
        }
    
        return $errors;
    }
    function checkDuplicateSubjectData($subject_code, $subject_name) {
        // Get database connection
        $conn = connectToDatabase();
    
        // Query to check if the subject_code already exists in the database
        $sql = "SELECT * FROM subjects WHERE subject_code = :subject_code OR subject_name = :subject_name";
        $stmt = $conn->prepare($sql);
    
        // Bind parameters
        $stmt->bindParam(':subject_code', $subject_code);
        $stmt->bindParam(':subject_name', $subject_name);
    
        // Execute the query
        $stmt->execute();
    
        // Fetch the results
        $existing_subject = $stmt->fetch(PDO::FETCH_ASSOC);
    
        // If a subject exists with the same code or name, return an error
        if ($existing_subject) {
            return ["Duplicate subject found: The subject code or name already exists."];
        }
    
        return [];
    }

        
    
    


function getSubjectByCode($subject_code) {
    $pdo = connectToDatabase();
    $query = "SELECT * FROM subjects WHERE subject_code = :subject_code";
    $stmt = $pdo->prepare($query);
    $stmt->execute([':subject_code' => $subject_code]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
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




// Check if the form is submitted via POST method
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize and assign the POST data to variables
    $subject_code = isset($_POST['subject_code']) ? $_POST['subject_code'] : null;
    $subject_name = isset($_POST['subject_name']) ? $_POST['subject_name'] : null;

    // Call the function to add the subject to the database
    addSubject($subject_code, $subject_name);
}

/**
 * Deletes a subject from the database based on its subject code.
 *
 * @param string $subject_code The code of the subject to delete.
 * @param string $redirectPage The page to redirect to after deletion.
 * @return void
 */
function deleteSubject($subject_code, $redirectPage) {
    try {
        // Get the database connection
        $pdo = connectToDatabase();

        // Prepare the SQL query to delete the subject
        $sql = "DELETE FROM subjects WHERE subject_code = :subject_code";
        $stmt = $pdo->prepare($sql);

        // Bind the parameter
        $stmt->bindParam(':subject_code', $subject_code, PDO::PARAM_STR);

        // Execute the query
        if ($stmt->execute()) {
            // Redirect to the specified page on success
            header("Location: $redirectPage");
            exit; // Ensure the script stops after redirection
        } else {
            // Output an error message if the query failed
            echo "<div class='alert alert-danger'>Failed to delete the subject with code $subject_code.</div>";
        }
    } catch (PDOException $e) {
        // Handle database connection or query errors
        echo "<div class='alert alert-danger'>Error: " . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8') . "</div>";
    }
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