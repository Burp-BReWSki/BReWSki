<html>
 <head>
  <title>PHP Test for Zend Active check</title>
 </head>
 <body>
 <?php 

$name = $_REQUEST['name'];

print '<p>Hello '; 

print $name;

print '</p>';

 if($_REQUEST['start_debug'] == 1)
 {
        echo 'Cannot resolve host abcd';
 }

?> 

 </body>
</html>
