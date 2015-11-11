Legal Things - Authorizer
==================

## Requirements

- [PHP](http://www.php.net) >= 5.5.0

_Required PHP extensions are marked by composer_

## Installation

The library can be installed using composer. Add the following to your `composer.json`:

    "repositories": [
        {
            "type": "vcs",
            "url": "https://github.com/legalthings/authorizer"
        }
    ],
    require: {
        "legalthings/authorizer": "~0.1.0"
    }


## Usage

**System A (Has resources which require authorization)**
``` php
use LegalThings/Authorizer;

class FooController
{
  public function __construct()
  {
    Authorizer::$globalSecret = 'some-secret-which-stays-the-same'; 
  }

  public function getAction($id)
  {
    $foo = Foo::fetch($id);
    if (!isset($foo)) return $this->notFound();

    if (isset($_GET['authzgen'])) {
      $encryptedSecret = Authorizer::sign('/some/resource', $_GET['authzgen']); // authzgen is a string with the format: {{public_key_url}};{{time_from}};{{time_to}}
      $this->output($encryptedSecret, 'text/plain');
      return;
    }

    if (isset($_GET['authz']) {
      $mayAccess = Authorizer::verify('/some/resource', $_GET['authz']); // authz is the decrypted secret

      if (!$mayAccess) return $this->forbidden();
      $this->output($foo);
    }
  }
}
```

**System B (Wants resources from system A)**
``` php
use LegalThings/Authorizer;

class Requester
{
  public function requestFooAction($id)
  {
    ...

    $encryptedSecret = FooService::requestPermission('/some/resource', 'http://requester.localhost/public.pem', $startTime, $endTime); // this request fills up the authzgen in system A. Also, times are unix timestamps

    $decryptedSecret = Authorizer::decrypt($encryptedSecret, 'path/to/private_key.pem'); // this request fills up authz in system A
    $foo = FooService::trustedRequest('/some/resource', $decryptedSecret);
  }
}
```
