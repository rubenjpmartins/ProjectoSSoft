<?php
$id_nilai=$_COOKIE['idn'];
$q_nilai="SELECT * FROM nilai INNER JOIN matapelajaran ON 
matapelajaran.id_matapelajaran = nilai.id_matapelajaran INNER JOIN siswa ON siswa.nis=nilai.nis 
INNER JOIN kelas ON kelas.id_kelas=nilai.id_kelas
WHERE id_nilai='$id_nilai'";
$q_nilai=mysqli_stmt_bind_param($q_nilai);
$hasil=mysqli_execute($q_nilai,$koneksi);
?>