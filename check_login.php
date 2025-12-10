<?php
session_start();

$page_title = 'Check login';

include 'includes/header.html';
include 'mysqli_connect.php';

if (isset($_SESSION['username'])) {
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'], $_POST['pass'])) {
    $username = trim($_POST['username']);
    $password = $_POST['pass'];

    // Prepared statement to avoid SQL injection
    $sql = "SELECT users_username, users_password FROM users WHERE users_username = ?";
    $stmt = mysqli_prepare($connection, $sql);

    if ($stmt === false) {
        die(mysqli_error($connection));
    }

    mysqli_stmt_bind_param($stmt, 's', $username);

    if (!mysqli_stmt_execute($stmt)) {
        mysqli_stmt_close($stmt);
        die(mysqli_error($connection));
    }

    $result = mysqli_stmt_get_result($stmt);

    if ($result && mysqli_num_rows($result) > 0) {
        $row = mysqli_fetch_assoc($result);

        // Verify the submitted password against the stored (hashed) password
        if (password_verify($password, $row['users_password'])) {
            $_SESSION['username'] = $row['users_username'];
            include 'includes/navbar.html';
            include 'includes/logged.php';
        } else {
            include 'includes/navbar.html';
            include 'includes/notlogged.php';
        }
    } else {
        include 'includes/navbar.html';
        include 'includes/notlogged.php';
    }

    if (isset($result) && is_object($result)) {
        mysqli_free_result($result);
    }
    mysqli_stmt_close($stmt);
} else {
    // Not a POST request or missing fields — show not-logged view
    include 'includes/navbar.html';
    include 'includes/notlogged.php';
}

mysqli_close($connection);

include 'includes/footer.html';
?>
