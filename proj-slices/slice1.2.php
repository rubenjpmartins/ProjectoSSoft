<?php
$nis=$_POST['nis'];
$query="SELECT *FROM siswa WHERE nis='$nis'";
$koneksi=mysql_real_escape_string($koneksi);
$q=mysql_query($query,$koneksi);
?>