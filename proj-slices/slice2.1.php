<?php
$nis=$_POST['nis'];
$q_sems="SELECT id_nilai,nis,semester FROM nilai WHERE nis='$nis'GROUP BY semester";
$q_sems=mysql_real_escape_string($q_sems);
$hasil=mysql_unbuffered_query($q_sems,$koneksi);
?>