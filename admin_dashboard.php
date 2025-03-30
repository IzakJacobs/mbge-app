
<?php
session_start();
if (!isset($_SESSION["admin"])) {
    header("Location: admin_login.php");
    exit();
}

$conn = new mysqli("localhost", "root", "", "visitor_system");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$message = "";
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = $_POST["email"];
    $pin = $_POST["pin"];

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || !preg_match('/^\d{6}$/', $pin)) {
        $message = "<p style='color:red;'>Invalid email or PIN (must be 6 digits).</p>";
    } else {
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $message = "<p style='color:red;'>User already exists.</p>";
        } else {
            $insert = $conn->prepare("INSERT INTO users (email, pin) VALUES (?, ?)");
            $insert->bind_param("ss", $email, $pin);
            if ($insert->execute()) {
                $message = "<p style='color:green;'>User registered successfully.</p>";
            } else {
                $message = "<p style='color:red;'>Error saving user.</p>";
            }
            $insert->close();
        }
        $stmt->close();
    }
}

$result = $conn->query("SELECT email, pin FROM users ORDER BY id DESC");
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Admin Dashboard - MBGE Visitor Access</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f4f7fa;
      padding: 20px;
    }
    h2 {
      text-align: center;
    }
    form {
      max-width: 500px;
      margin: auto;
      background: white;
      padding: 20px;
      border-radius: 10px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    input {
      width: 100%;
      padding: 12px;
      margin: 10px 0;
      font-size: 16px;
      border-radius: 8px;
      border: 1px solid #ccc;
    }
    button {
      width: 100%;
      padding: 12px;
      font-size: 16px;
      background: #007bff;
      color: white;
      border: none;
      border-radius: 8px;
      cursor: pointer;
    }
    button:hover {
      background: #0056b3;
    }
    table {
      width: 100%;
      margin-top: 30px;
      border-collapse: collapse;
    }
    th, td {
      border: 1px solid #ccc;
      padding: 10px;
      text-align: left;
    }
    th {
      background: #f0f0f0;
    }
  </style>
</head>
<body>
  <h2>Admin Dashboard</h2>
  <form method="POST">
    <h3>Register New User</h3>
    <?php echo $message; ?>
    <input type="email" name="email" placeholder="User Email" required>
    <input type="text" name="pin" placeholder="6-digit PIN" maxlength="6" required>
    <button type="submit">Register User</button>
  </form>

  <h3 style="max-width:500px; margin:auto; margin-top:40px;">Registered Users</h3>
  <table>
    <tr><th>Email</th><th>PIN</th></tr>
    <?php while ($row = $result->fetch_assoc()): ?>
      <tr>
        <td><?php echo htmlspecialchars($row["email"]); ?></td>
        <td><?php echo htmlspecialchars($row["pin"]); ?></td>
      </tr>
    <?php endwhile; ?>
  </table>
</body>
</html>
<?php $conn->close(); ?>
