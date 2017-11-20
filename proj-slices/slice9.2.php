<?php
$nis=$_POST['nis'];
while ($indarg == "") {
    $query="SELECT *FROM siswa WHERE nis='$nis'";
}
$query=mysql_real_escape_string($query);
$q=mysql_query($query,$koneksi);
?>