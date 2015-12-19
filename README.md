Legal Things - Authorizer
==================

With the authorizer library, a webservice can generate an access token for a resource. The library uses [public key 
cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography) to encrypt the access token. This means it can only be
used by a system that has the private decryption key to get access to the resource.

## Requirements

- [PHP](http://www.php.net) >= 5.5.0

_Required PHP extensions are marked by composer_

## Installation

The library can be installed using composer.

    composer require legalthings/authorizer

## How it works

System A has a resource which requires authorization. It will only allow system B access to the resource. Clients are 
allowed to use the resource, but don't have direct access to it. A client using both system A and system B, wants system A
to share a specific resource with system B.

Upon request by the client, system A will generate an access token for the resource. It download the public encryption key 
of system B and uses it to encrypt the access token. This encrypted token returned to the client.

The client passes the link to the resource and the encrypted token to system B. Sytem B will decrypt the encrypted token
and use it to download the resource.

### Example

**System A (has resources)**
```php
use LegalThings/Authorizer;

Authorizer::$globalSecret = 'some-secret-which-stays-the-same'; 

$pdf = basename($_GET['pdf']);

if (isset($_GET['authzgen'])) {
  if (parse_url($_GET['authzgen'], PHP_URL_HOST) !== 'system-b.example.com') {
    http_response_code(403);
    echo "Will only grant access for system-b.example.com";
    exit();
  }

  $encryptedToken = Authorizer::sign($pdf, $_GET['authzgen']); // authzgen is a string with the format: {{public_key_url}};{{time_from}};{{time_to}}
  
  header('Content-Type: text/plain');
  echo $encryptedToken;
  exit();
}

$mayAccess = isset($_GET['authz']) && Authorizer::verify($pdf, $_GET['authz']); // authz is the decrypted secret

if (!$mayAccess) {
  http_response_code(403);
  echo "Access denied";
  exit();
}

// Get and output resource
header('Content-Type: application/pdf');
readfile('path/to/resources/' . $pdf);
```

**System B (can download and use resources)**
```php
use LegalThings/Authorizer;

$link = $_POST['link'];

if (isset($_POST['token'])) {
  $encryptedToken = $_POST['token'];
  $token = Authorizer::decrypt($encryptedSecret, 'path/to/private_key.pem');
  $link .= (strstr($link, '?') ? '&' : '?') . 'authz=' . $token;
}

$pdf = file_get_contents($link);

// Let's do something with the PDF
$username = $_SESSION['username'];
file_put_contents("../userdata/$username/" . md5(microtime()) . ".pdf", $pdf);
```

**Client**
```sh
LINK="http://system-a.example.com/get-pdf.php?pdf=abc.pdf"
ENCRYPTED_TOKEN=$(curl --get "$LINK" --data-urlencode "authzgen=http://system-b.example.com/authorizer.pem")
curl --post "http://system-b.example.com/use-pdf.php" --data-urlencode "link=$LINK" --data-urlencode "authz=$ENCRYPTED_TOKEN"
```

## Why is this useful?

This is a way to allow two systems to share resources between them, with minimal coupling.

System B can use any PDF on the internet. By implementing `Authorizer` it gives services that want to share a resource only
with system B the means to do so.
