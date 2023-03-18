# Rest-full Security

## About Rest-full Security

Rest-full Security is a small part of the Rest-Full framework.

You can find the application at: [rest-full/app](https://github.com/rest-full/app) and you can also see the framework skeleton at: [rest-full/rest-full](https://github.com/rest-full/rest-full).

## Installation

* Download [Composer](https://getcomposer.org/doc/00-intro.md) or update `composer self-update`.
* Run `php composer.phar require rest-full/security` or composer installed globally `compser require rest-full/security` or composer.json `"rest-full/security": "1.0.0"` and install or update.

## Usage

This Security
```
<?php

require_once __DIR__.'/../vendor/autoload.php';
require_once __DIR__.'/../config/pathServer.php';

use Restfull\Security\Security;

$security = new Security();
echo $security->salt()->getSalt()."<br>".$security->getRand(5);
```
## License

The rest-full framework is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).