<?php

$translator_dir = "/src/serval/src/translator/";

$cmd = "$translator_dir" . "translator -x -p 8080 -s 0x000019f:128 >/dev/null 2>&1 &";
echo "Strating translator: " . $cmd . '<br><br><br>';
$s = exec($cmd, $out, $return_val);

$cmd = "ps ax | grep translator";
echo "$cmd" . '<br>';
$s = exec($cmd, $out, $return_val);

foreach ($out as $o) {
  #print_r(preg_split('/\s+/', $o));
  echo $o . "<br>";
}

?>