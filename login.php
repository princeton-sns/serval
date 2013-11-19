<?php

final class LoginValidator {

  private function __construct() {
    
  }

  public static function validate ($username, $password) {
    $errors = array();
    $username = trim($username);
    if (!$username) {
      $errors[] = new Error('username', 'Empty username!');
    } elseif (strlen($username) < 3) {
      $errors[] = new Error('username', 'Username cannot be less than 3 characters!');
    } elseif (strlen($username) > 30) {
      $errors[] = new Error('username', 'Username cannot be more than 30 characters!');
    } elseif (!preg_match('/^[A-Za-z0-9_]+$/', $username)) {
      $errors[] = new Error('username', 'unacceptable charaters!');
    } elseif (!trim($password)) {
      $errors[] = new Error('password', 'Password cannot be empty!');
    } else {
      // check whether user exists or not
      if (strcmp($username, 'serval') != 0) {
	$errors[] = new Error('user', 'User does not exist!');
	//echo 'User does not exist!';
	  //echo '<br>';
	  //return;
	} 
       
      if (strcmp($password, 'serval') != 0) {
	$errors[] = new Error('password', 'Incorrect password!');
	//echo 'Incorrect password!';
	//  echo '<br>';
	//  return;
      }
    }

    return $errors;

  }
}

final class Error {
  private $source;
  private $message;

  /**
   * Create new error.
   * @param mixed $source source of the error
   * @param string $message error message
   */

  function __construct($source, $message) {
    $this->source = $source;
    $this->message = $message;
  }

  /**
   * Get source of the error.
   * @return mixed source of the error
   */
  public function getSource() {
    return $this->source;
  }

  /**
   * Get error message.
   * @return string error message
   */
  public function getMessage() {
    return $this->message;
  }
}

$username = null;
$password = null;

$msg = "";

if (isset($_POST['username']) && isset($_POST['password'])) {
  $username = $_POST['username'];
  $password = $_POST['password'];

  // validate

  $errors = LoginValidator::validate($username, $password);

  foreach ($errors as $e) {
    $msg .= $e->getMessage()."<br>";
  }

  if ($msg != "") {
    echo $msg;
  }
  else {
    header('location:controller.php');
  }
}

?>