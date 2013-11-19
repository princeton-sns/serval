<?php

require('db.php');

$db = get_serval_db();


$rs = $db->query("SELECT * from ServiceRouter");

while ($row = $rs->fetch()) {
  print_r($row);
  echo '<br>';
}

echo '<br>';

$IP = get_router_address($db, "sns1");

echo $IP;

$db = null;

?>