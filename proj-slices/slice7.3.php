<?php
$nis=$_POST['nis'];
$query1="SELECT *FROM siswa WHERE nis='";
$query2="$nis'";
$query=$query1 . $query2;
$query=mysql_escape_string($query);
$q=mysql_query($query,$koneksi);
?>