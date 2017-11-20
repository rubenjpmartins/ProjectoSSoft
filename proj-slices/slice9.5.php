<?php
$nis=$_POST['nis'];
while ($indarg == "") {
    $query=mysql_real_escape_string($query);
    $query="SELECT *FROM siswa WHERE nis='$nis'";
}
$q=mysql_query($query,$koneksi);
?>