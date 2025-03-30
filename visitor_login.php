
<?php
session_start();
$conn = new mysqli("localhost", "root", "", "visitor_system");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$loginError = "";
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $email = $_POST["email"];
    $pin = $_POST["pin"];

    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? AND pin = ?");
    $stmt->bind_param("ss", $email, $pin);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $_SESSION["user"] = $email;
        header("Location: visitor.html");
        exit();
    } else {
        $loginError = "Invalid email or PIN.";
    }

    $stmt->close();
}
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Visitor Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #e9f0f5;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
    }
    .login-container {
      background: white;
      padding: 30px 20px;
      border-radius: 16px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.1);
      width: 95%;
      max-width: 400px;
      text-align: center;
    }
    img {
      width: 160px;
      margin-bottom: 20px;
    }
    input[type="email"], .pin-container input {
      width: 100%;
      padding: 14px;
      margin: 10px 0;
      font-size: 16px;
      border: 1px solid #ccc;
      border-radius: 8px;
      box-sizing: border-box;
    }
    .pin-container {
      display: flex;
      justify-content: space-between;
      margin: 10px 0 20px;
    }
    .pin-container input {
      width: 45px;
      text-align: center;
      font-size: 20px;
    }
    button {
      width: 100%;
      padding: 14px;
      font-size: 16px;
      background: #007bff;
      color: white;
      border: none;
      border-radius: 8px;
      margin-top: 15px;
      cursor: pointer;
    }
    button:hover {
      background: #0056b3;
    }
    .error {
      color: red;
      margin-bottom: 10px;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <img src="logo.png" alt="MBGE Logo">
    <h2>Welcome Back</h2>
    <?php if ($loginError): ?>
      <div class="error"><?php echo $loginError; ?></div>
    <?php endif; ?>
    <form method="POST">
      <input type="email" name="email" placeholder="Email address" required>
      <div class="pin-container">
        <?php for ($i = 0; $i < 6; $i++): ?>
          <input type="text" maxlength="1" name="pin_digit[]" pattern="[0-9]*" inputmode="numeric" required>
        <?php endfor; ?>
      </div>
      <button type="submit">Login</button>
    </form>
  </div>
  <script>
    const pinInputs = document.querySelectorAll('.pin-container input');
    pinInputs.forEach((input, index) => {
      input.addEventListener('input', () => {
        if (input.value.length === 1 && index < pinInputs.length - 1) {
          pinInputs[index + 1].focus();
        }
      });
    });

    // Join pin digits into one hidden input before submit
    document.querySelector("form").addEventListener("submit", function(e) {
      const digits = Array.from(pinInputs).map(input => input.value).join("");
      const pinInput = document.createElement("input");
      pinInput.type = "hidden";
      pinInput.name = "pin";
      pinInput.value = digits;
      this.appendChild(pinInput);
    });
  </script>
</body>
</html>
