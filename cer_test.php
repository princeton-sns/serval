<?php

#phpinfo();

#echo "<a href=https://128.112.7.80/add_service.php?prefix=1234&IP=12.3.4.5>aaa</a>";

$url = "https://128.112.7.80/show_service.php?prefix=54321&IP=4.3.2.1";

$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_PORT, 443);
curl_setopt($ch, CURLOPT_VERBOSE, 0);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_SSLVERSION, 3);
curl_setopt($ch, CURLOPT_SSLCERTPASSWD, "realmzx");
curl_setopt($ch, CURLOPT_SSLCERT, "/usr/local/apache/httpd/conf/sns1_cer/client.crt");
curl_setopt($ch, CURLOPT_CAPATH, "/usr/local/apache/httpd/conf/sns1_cer/client.pem");
curl_setopt($ch, CURLOPT_SSLCERTTYPE, 'PEM');
curl_setopt($ch, CURLOPT_SSLKEY, "/usr/local/apache/httpd/conf/sns1_cer/client.key");
curl_setopt($ch, CURLOPT_CAINFO, "/usr/local/apache/httpd/conf/sns1_cer/ca.crt");
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$response = curl_exec($ch);

if (!curl_errno($ch)) {
  $info = curl_getinfo($ch);
  echo 'Took ' . $info['total_time'] . 'seconds to send a request to ' . $info['url']; } else {
  echo 'Curl error: ' . curl_error($ch);
}

curl_close($ch);

echo $response;

?>