<?php
session_start();
// semgrep-disable-next-line requires-login
if (!isset($_SESSION['user_id']) || !isset($_SESSION['username'])) {
    http_response_code(403);
    echo "You must be logged in to perform this action.";
    exit();

}


$page_title = "Delete pictures";

include 'mysqli_connect.php';
include 'includes/header.html';
include 'includes/navbar.html';


if (isset($_POST['pictures_name'])) {
    $pictures_name = basename(trim($_POST['pictures_name']));
    $username = $_SESSION['username'];

    $stmt = mysqli_prepare($connection, "SELECT users_id FROM users WHERE users_username = ?");
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $user_id);

    if (mysqli_stmt_fetch($stmt)) {
        mysqli_stmt_close($stmt);

        $del_stmt = mysqli_prepare($connection, "DELETE FROM pictures WHERE pictures_name = ? AND id_users = ?");
        mysqli_stmt_bind_param($del_stmt, "si", $pictures_name, $user_id);
        mysqli_stmt_execute($del_stmt);

        if (mysqli_stmt_affected_rows($del_stmt) > 0) {
            $path = __DIR__ . '/uploads/' . $pictures_name;
            if (is_file($path) && is_writable($path) && unlink($path)) {
                echo "Removed picture " . htmlspecialchars($pictures_name) . "<br>";
            } else {
                echo "Record removed but file not found or could not be deleted: " . htmlspecialchars($pictures_name) . "<br>";
            }
        } else {
            echo "No matching picture found or permission denied.";
        }

        mysqli_stmt_close($del_stmt);
    } else {
        mysqli_stmt_close($stmt);
        echo "User not found.";
    }
}

$list_stmt = mysqli_prepare(
    $connection,
    "SELECT pictures.pictures_name
     FROM pictures
     INNER JOIN users ON pictures.id_users = users.users_id
     WHERE users.users_username = ?"
);
mysqli_stmt_bind_param($list_stmt, "s", $_SESSION['username']);
mysqli_stmt_execute($list_stmt);
mysqli_stmt_store_result($list_stmt);
mysqli_stmt_bind_result($list_stmt, $pic_name);

echo "<form action=\"\" method=\"POST\">";
echo "<select name=\"pictures_name\">";

if (mysqli_stmt_num_rows($list_stmt) > 0) {
    while (mysqli_stmt_fetch($list_stmt)) {
        echo "<option value=\"" . htmlspecialchars($pic_name) . "\">" . htmlspecialchars($pic_name) . "</option>";
    }
} else {
    echo "<option disabled>No pictures available</option>";
}

echo "</select>";
echo "<input type=\"submit\" value=\"Delete picture\">";
echo "</form>";

mysqli_stmt_close($list_stmt);

include 'includes/footer.html';

mysqli_close($connection);
unset($connection);
?>