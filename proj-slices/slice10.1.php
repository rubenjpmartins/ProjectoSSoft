<?php
$nis=$_POST['nis'];
while ($indarg == "") {
      $query="SELECT *FROM siswa WHERE nis='$arg3'";
      $arg3 = $arg2;
      $arg2 = $arg1;
      $arg1 = $nis;
	  $arg1=mysql_real_escape_string($arg1);
      $indarg = substr($indarg,1);
}
$q=mysql_query($query,$koneksi);
?>