<?php

require_once __DIR__.'/../vendor/autoload.php';
require_once __DIR__.'/../config/pathServer.php';

use Restfull\Security\Security;

$security = new Security();
echo $security->salt()->getSalt()."<br>".$security->getRand(5);