<?php
include '../../functions.php'; // Include the functions
require '../partials/header.php';

$logoutPage = '../logout.php';
$dashboardPage = '../dashboard.php';
require '../partials/side-bar.php';

?>

<div class="col-md-9 col-lg-10">
    <!-- Breadcrumb Navigation -->
    <h3 class="text-left mb-5 mt-5">Add a Subject</h3>

    <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
            <li class="breadcrumb-item" aria-current="page"><a href="../dashboard.php">Dashboard</a></li>
            <li class="breadcrumb-item active" aria-current="page">Add Subject</li>
        </ol>
    </nav>

    <?php
    // Process the form submission
    if (isPost()) {
        $subject_code = postData("subject_code");
        $subject_name = postData("subject_name");

        // Basic validation before adding the subject
        if (!empty($subject_code) && !empty($subject_name)) {
            addSubject($subject_code, $subject_name);
        } else {
            echo "<div class='alert alert-danger'>Please fill in all fields.</div>";
        }
    }
    ?>

    <!-- Add Subject Form -->
    <div class="card p-4 mb-5">
        <form method="POST">
            <div class="mb-3">
                <label for="subject_code" class="form-label">Subject Code</label>
                <input type="text" class="form-control" id="subject_code" name="subject_code" required>
            </div>
            <div class="mb-3">
                <label for="subject_name" class="form-label">Subject Name</label>
                <input type="text" class="form-control" id="subject_name" name="subject_name" required>
            </div>
            <button type="submit" class="btn btn-primary btn-sm w-100">Add a Subject</button>
        </form>
    </div>

    <!-- Subject List Table -->
    <div class="card p-4">
        <h3 class="card-title text-left">Subject List</h3>
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Subject Code</th>
                    <th>Subject Name</th>
                    <th>Options</th>
                </tr>
            </thead>
            <tbody>
                <?php
                // Fetch and display subjects from the database
                $subjects = fetchSubjects();
                if (!empty($subjects)) :
                    foreach ($subjects as $subject) :
                ?>
                        <tr>
                            <td><?= htmlspecialchars($subject['subject_code']) ?></td>
                            <td><?= htmlspecialchars($subject['subject_name']) ?></td>
                            <td>
                                <a href="editSubject.php?subject_code=<?= urlencode($subject['subject_code']) ?>" class="btn btn-primary btn-sm">Edit</a>
                                <a href="deleteSubject.php?subject_code=<?= urlencode($subject['subject_code']) ?>" class="btn btn-danger btn-sm">Delete</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php else : ?>
                    <tr>
                        <td colspan="3" class="text-center">No subjects found.</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<?php
require '../partials/footer.php';
?>