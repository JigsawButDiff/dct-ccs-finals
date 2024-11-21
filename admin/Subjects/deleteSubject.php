<?php

// Include necessary files and functions
include '../../functions.php';
include '../partials/header.php';
include '../partials/side-bar.php';

// Define page paths
$dashboardPage = '../dashboard.php';
$logoutPage = '../logout.php';
$subjectPage = '../addSubject.php';


// Retrieve subject data based on the subject_code from the query string
$subject_code = $_GET['subject_code'] ?? null;
if (!$subject_code) {
    header("Location: $subjectPage"); // Redirect to subject page if no subject_code is provided
    exit();
}

$subject_data = getSubjectByCode($subject_code);
if (!$subject_data) {
    echo "<div class='alert alert-danger'>Subject not found!</div>";
    exit();
}


if (isPost()) {
    deleteSubject($subject_data['subject_code'], $subjectPage);
}

?>

<div class="col-md-9 col-lg-10">

    <h3 class="text-left mb-5 mt-5">Delete Subject</h3>

    <!-- Breadcrumb Navigation -->
    <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
            <li class="breadcrumb-item"><a href="<?= htmlspecialchars($dashboardPage) ?>">Dashboard</a></li>
            <li class="breadcrumb-item"><a href="addSubject.php">Add Subject</a></li>
            <li class="breadcrumb-item active" aria-current="page">Delete Subject</li>
        </ol>
    </nav>

    <div class="border p-5">
        <!-- Confirmation Message -->
        <p class="text-left">Are you sure you want to delete the following subject record?</p>
        <ul class="text-left">
            <li><strong>Subject Code:</strong> <?= htmlspecialchars($subject_data['subject_code']) ?></li>
            <li><strong>Subject Name:</strong> <?= htmlspecialchars($subject_data['subject_name']) ?></li>
        </ul>

        <!-- Confirmation Form -->
        <form method="POST" action="deleteSubject.php?subject_code=<?= htmlspecialchars($_GET['subject_code'], ENT_QUOTES, 'UTF-8') ?>">
    <a href="addSubject.php" class="btn btn-secondary">Cancel</a>
    <button type="submit" class="btn btn-danger">Delete Subject Record</button>
    
</form>

    </div>

</div>



<?php
include '../partials/footer.php';
?>