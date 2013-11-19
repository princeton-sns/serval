<?php

final class ServiceValidator {

  private function __construct() {

  }

  public static function validate ($prefix, $IP) {
    $errors = array();
    $prefix = trim($prefix);

    $preg="\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}";
    
    if (!$prefix) {
      $errors[] = new Error('prefix', 'Empty prefix!');
    } #elseif (!preg_match('/^[0-9]+$/', $prefix)) {
      #$errors[] = new Error('prefix', 'Prefix: ' . $prefix . 'Bad prefix format!');
#    } 
    elseif (!trim($IP)) {
      $errors[] = new Error('IP address', 'Empty IP address!');
    } elseif (!filter_var($IP, FILTER_VALIDATE_IP)) {
      $errors[] = new Error('IP address', 'Bad IP format!');
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

$cmd = "";

$msg = "";

if (!isset($_GET['prefix']) && !isset($_POST['prefix'])) {
  echo "prefix unset!";
} elseif (!isset($_GET['IP']) && !isset($_POST['IP'])) {
  echo "IP unset!";
} else {
  if (isset($_GET['prefix']))
    $prefix = $_GET['prefix'];
  else
    $prefix = $_POST['prefix'];

  if (isset($_GET['IP']))
    $IP = $_GET['IP'];
  else
    $IP = $_POST['IP'];

  if (isset($_GET['prefix_bits']))
    $prefix_bits = $_GET['prefix_bits'];
  else if (isset($_POST['prefix_bits']))
    $prefix_bits = $_POST['prefix_bits'];
  else $prefix_bits = 256;

  if (isset($_GET['service_type']))
    $service_type = $_GET['service_type'];
  else if (isset($_POST['service_type']))
    $service_type = $_POST['service_type'];
  else $service_type = "service";

    // validate
 
    $errors = ServiceValidator::validate($prefix, $IP);

  foreach ($errors as $e) {
    $msg .= $e->getMessage()."<br>";
  }

  if ($msg != "") {
    echo $msg;
  }
  else {
    $cmd .= "/src/serval/src/tools/serv service add " . $prefix. ":" . $prefix_bits . " " . $IP;
    $s = exec($cmd, $out, $return_val);
    $msg .= $cmd . '<br>';
    foreach ($out as $o) {
      echo $o."<br>";
      $msg .= $o . '<br>';
    }
    $msg .= "Successfully added service rule: ".$prefix." -> ".$IP;
    echo $msg;
  }
} 

?>