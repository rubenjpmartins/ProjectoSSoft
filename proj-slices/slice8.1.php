<?php
$nis=$_POST['nis'];
if ($indarg == "") {
	$query="SELECT *FROM siswa WHERE nis='$nis'";
	$query=mysql_escape_string($query);
}
else {
	$query="SELECT *FROM siswa WHERE nis='$nis'";
}
$q=mysql_query($query,$koneksi);
?>