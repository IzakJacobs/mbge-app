
<?php
session_start();
session_destroy();
header("Location: visitor_login.php");
exit();
?>
