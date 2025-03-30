
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Admin Login - MBGE Visitor Access</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f1f4f8;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
    }
    .login-box {
      background: #fff;
      padding: 30px;
      border-radius: 12px;
      box-shadow: 0 0 10px rgba(0,0,0,0.1);
      width: 90%;
      max-width: 400px;
    }
    h2 {
      text-align: center;
      margin-bottom: 20px;
    }
    input {
      width: 100%;
      padding: 12px;
      margin: 10px 0;
      font-size: 16px;
      border: 1px solid #ccc;
      border-radius: 8px;
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
  </style>
</head>
<body>
  <div class="login-box">
    <h2>Admin Login</h2>
    <form method="POST" action="admin_login.php">
      <input type="email" name="email" placeholder="Admin Email" required>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Login</button>
    </form>
    <?php
      if ($_SERVER["REQUEST_METHOD"] === "POST") {
          $email = $_POST["email"];
          $password = $_POST["password"];
          
          $conn = new mysqli("localhost", "root", "", "visitor_system");
          if ($conn->connect_error) {
              die("Connection failed: " . $conn->connect_error);
          }
          
          $stmt = $conn->prepare("SELECT password FROM admins WHERE email = ?");
          $stmt->bind_param("s", $email);
          $stmt->execute();
          $stmt->store_result();

          if ($stmt->num_rows > 0) {
              $stmt->bind_result($hashedPassword);
              $stmt->fetch();
              if (password_verify($password, $hashedPassword)) {
                  session_start();
                  $_SESSION["admin"] = $email;
                  header("Location: admin_dashboard.php");
                  exit();
              } else {
                  echo "<p style='color:red;'>Invalid password.</p>";
              }
          } else {
              echo "<p style='color:red;'>Admin not found.</p>";
          }

          $stmt->close();
          $conn->close();
      }
    ?>
  </div>
</body>
</html>
