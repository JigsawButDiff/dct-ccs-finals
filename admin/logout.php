<?php

  // Include the functions file to access the logout function
  require '../functions.php';
  
  // Specify the login page to redirect to after logout
  $loginPage = '../index.php';
  
  // Call the logout function, passing in the login page
  logout($loginPage);
  ?>
?>