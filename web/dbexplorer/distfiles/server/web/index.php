<html>
<h1>Under development</h1>

<?php
define("__INDIRECT__",true);

session_start();

if(!$level) $level = 0;

include_once "level_checker.php";

if(preg_match('/(.*):(.*)/', $_GET['normal'].$_GET['admin'])) exit("Hmm, are you sure?");

// You can only include php file if you are not an admin!
if($level == 1){
    include_once $_GET['normal'].".php";
}

if($level == 2) {
    include $_GET['admin'];
}

?>