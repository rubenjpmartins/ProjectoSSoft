<?php
$nis=$_POST['nis'];
$query1="SELECT *FROM siswa WHERE nis='";
$query2="$nis'";
$query2=mysql_escape_string($query2);
$query=$query1 . $query2;
$q=mysql_query($query,$koneksi);
?>