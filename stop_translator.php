<?php

$translator_dir = "/src/serval/src/translator/";

$cmd = "ps ax | grep /translator/translator";

$s = exec($cmd, $out, $return_val);

foreach ($out as $o) {
  $r = preg_split('/\s+/', $o);
  if (isset($r[2]) && $r[2] == 'Sl') {
    $pid = $r[0];
    $cmd = "kill -7 $pid";
    $s = exec($cmd, $out1, $return_val1);

    echo '<br><br><br>';
    $cmd = "ps ax | grep translator: ";
    echo "$cmd" . '<br>';
    foreach ($out1 as $o1) {
      echo $o1 . '<br>';
    }
  }
}

?>