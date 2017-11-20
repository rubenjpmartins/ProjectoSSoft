<?php
$nis=$_POST['nis'];
while ($indarg == "") {
      $query="SELECT *FROM siswa WHERE nis='$arg3'";
      $arg3 = $arg2;
	  $arg3=mysql_real_escape_string($arg3);
      $arg2 = $arg1;
      $arg1 = $nis;
      $indarg = substr($indarg,1);
}
$q=mysql_query($query,$koneksi);
?>