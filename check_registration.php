<?php
// Updated check_registration.php (based on ref 8760d038c60fb89eaf1dfae863671247db0c6df3)

session_start();

$page_title = "Check registration";

include 'mysqli_connect.php';
include 'includes/header.html';
include 'includes/navbar.html';

if (isset($_SESSION['username'])) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $password = isset($_POST['pass']) ? $_POST['pass'] : '';

    if ($username === '' || $password === '') {
        include 'includes/error.php';
    } else {
        $sql_check = "SELECT users_username FROM users WHERE users_username = ? LIMIT 1";
        if ($stmt = mysqli_prepare($connection, $sql_check)) {
            mysqli_stmt_bind_param($stmt, "s", $username);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_store_result($stmt);

            if (mysqli_stmt_num_rows($stmt) > 0) {
                // Username already exists
                mysqli_stmt_close($stmt);
                include 'includes/notregistered.php';
            } else {
                // Username does not exist -> create user with hashed password
                mysqli_stmt_close($stmt);

                $hashed_password = password_hash($password, PASSWORD_DEFAULT);

                $sql_insert = "INSERT INTO users (users_username, users_password) VALUES (?, ?)";
                if ($insert_stmt = mysqli_prepare($connection, $sql_insert)) {
                    mysqli_stmt_bind_param($insert_stmt, "ss", $username, $hashed_password);

                    if (mysqli_stmt_execute($insert_stmt)) {
                        mysqli_stmt_close($insert_stmt);
                        include 'includes/new_registration.php';
                    } else {
                        // Insert failed
                        mysqli_stmt_close($insert_stmt);
                        include 'includes/error.php';
                    }
                } else {
                    // Prepare failed
                    include 'includes/error.php';
                }
            }
        } else {
            // Prepare failed
            include 'includes/error.php';
        }
    }
}

// Close DB connection and include footer (preserve original behavior)
if (isset($connection) && is_resource($connection) || $connection instanceof mysqli) {
    mysqli_close($connection);
}

include 'includes/footer.html';
?>