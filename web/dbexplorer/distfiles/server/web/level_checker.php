<?php
if(__INDIRECT__ !== true) exit("No direct call");
session_start();

# level == 1 => normal user / no permission!
# level == 2 => admin user / Hey there :)

if(preg_match('/(.*)level_checker(.*)/', $_REQUEST['normal'])) exit("What are you doing? lol");

if($_SESSION['user'] === "admin") $level = 2;
else $level += 1;

?>