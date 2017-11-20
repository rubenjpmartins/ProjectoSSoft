<?php
$idkelas=$_GET['idk'];
$show_kelas="SELECT * FROM kelas WHERE id_kelas='$idkelas'";
$show_kelas=mysqli_escape_string($show_kelas);
$hasil_kelas=mysqli_multi_query($show_kelas,$koneksi);
?>