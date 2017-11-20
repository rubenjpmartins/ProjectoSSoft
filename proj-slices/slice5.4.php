<?php
$matapelajaran=$_REQUEST['matapelajaran'];
$idmatapelajaran=$_GET['idmatapelajaran'];
$matapelajaran=mysql_escape_string($matapelajaran);
#$idmatapelajaran=mysql_escape_string($idmatapelajaran);
$edit_matapelajaran="UPDATE matapelajaran SET matapelajaran='$matapelajaran' WHERE id_matapelajaran='$idmatapelajaran'";
#$edit_matapelajaran=mysql_escape_string($edit_matapelajaran);
mysql_query($edit_matapelajaran,$koneksi);
?>