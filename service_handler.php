<?php

final class ServiceValidator {

  private function __construct() {

  }

  public static function validate ($prefix, $IP, $machine) {
    $errors = array();
    $prefix = trim($prefix);
    
    if (!$prefix) {
      $errors[] = new Error('prefix', 'Empty prefix!');
    } elseif (!preg_match('/^[0-9]+$/', $prefix)) {
      $errors[] = new Error('prefix', 'Bad prefix format!');
    } elseif (!trim($IP)) {
      $errors[] = new Error('IP address', 'Empty IP address!');
    } elseif (strcmp($machine, 'Please select your machine') == 0) {
      $errors[] = new Error('machine', 'Please select your machine...');
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

$prefix = null;
$IP = null;
$machine = null;

$msg = "";

if (isset($_POST['prefix']) && isset($_POST['dstIP'])) {
    $prefix = $_POST['prefix'];
    $IP = $_POST['dstIP'];
    $machine = $_POST['machineList'];

    // validate
 
    $errors = ServiceValidator::validate($prefix, $IP, $machine);

  foreach ($errors as $e) {
    $msg .= $e->getMessage()."<br>";
  }

  if ($msg != "") {
    echo $msg;
  }
  else {
    $msg .= "Successfully added service rule on machine ".$machine.": ".$prefix." -> ".$IP;
    echo $msg;
  }
} else {
  
  echo "Bad parameters!";
}

?>