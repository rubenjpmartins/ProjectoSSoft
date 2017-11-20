<?php
$nis=$_POST['nis'];
$query="SELECT *FROM siswa WHERE nis='$nis'";
if ($indarg == "") {
}
else {
	$query=mysql_escape_string($query);
}
$q=mysql_query($query,$koneksi);
?>