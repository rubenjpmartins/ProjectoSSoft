<?php
$nis=$_POST['nis'];
while ($indarg == "") {
      $query="SELECT *FROM siswa WHERE nis='$arg3'";
      $arg3 = $arg2;
      $arg2 = $arg1;
      $arg1 = $nis;
      $indarg = substr($indarg,1);
}
$query=mysql_real_escape_string($query);
$q=mysql_query($query,$koneksi);
?>