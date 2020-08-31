<?php

namespace LegalThings;

/**
 * Interface to the Authorizer API
 */
class Authorizer
{
    /**
     * A secret string, should be configured once
     * @var string
     */
    public static $globalSecret;

    /**
     * Path to the private key of the current application
     * @var string
     */
    public static $privateKeyPath;

    /**
     * Path to the public key of the current application
     * @var string
     */
    public static $publicKeyPath;


    /**
     * Sign a resource, granting access to a specific client
     * 
     * @param string   $allowedResource
     * @param string   $authzgen         String with the format: {{certificate_url}};{{time_from}};{{time_to}}
     *                                   Time restrictions are unix timestamps, but may be omitted 
     * @return string  $encryptedSecret  An utf8_encoded encrypted secret
     */
    public static function sign($allowedResource, $authzgen, $handler = null)
    {
        if (!isset(self::$globalSecret)) trigger_error('$globalSecret is not set', E_USER_WARNING);

        list($cerfiticateUrl, $timeStart, $timeEnd) = explode(';', $authzgen) + [null, null, null];
        $opts = $handler !== null ? ['handler' => $handler] : [];

        $publicKey = self::downloadSigningKey($cerfiticateUrl, $opts);

        $resourceSecret = join(';', [
            $timeStart,
            $timeEnd,
            self::generateChecksum($allowedResource, $timeStart, $timeEnd)
        ]);

        openssl_public_encrypt($resourceSecret, $encryptedSecret, $publicKey);
        
        self::clearOpenSSLErrors();

        return base64_encode($encryptedSecret);
    }

    /**
     * Decrypt an encrypted secret
     * 
     * @param string   $encryptedSecret  An utf8_encoded encrypted secret with the format:
     *                                   {{resource}};{{time_from}};{{time_to}};{{hash}}
     *
     * @return string  $decryptedSecret  String with the format: {{time_from}};{{time_to}};{{checksum}}
     */
    public static function decrypt($encryptedSecret)
    {
        openssl_private_decrypt(base64_decode($encryptedSecret), $decryptedSecret, self::getPrivateKey());

        return $decryptedSecret;
    }

    /**
     * Verify if a resource may be accessed by the client
     * 
     * @param string    $allowedResource
     * @param string    $decryptedSecret  can be retrieved with static::decrypt()
     * @return boolean
     */
    public static function verify($allowedResource, $decryptedSecret)
    {
        $currentTime = time();

        list($timeStart, $timeEnd, $checksum) = explode(';', $decryptedSecret) + [null, null, null];

        if ($checksum !== self::generateChecksum($allowedResource, $timeStart, $timeEnd)) return false;

        $timeStart = strlen($timeStart) > 0 ? (int)$timeStart : ($currentTime - 1);
        $timeEnd = strlen($timeEnd) > 0 ? (int)$timeEnd : ($currentTime + 1);

        if ($currentTime < $timeStart || $currentTime > $timeEnd) return false;

        return true;
    }

    /**
     * Generates a checksum
     * 
     * @param string   $allowedResource
     * @param string   $timeStart
     * @param string   $timeEnd
     * @return string
     */
    protected static function generateChecksum($allowedResource, $timeStart, $timeEnd)
    {
        return hash('sha256', $allowedResource . $_SERVER['HTTP_HOST'] . $timeStart . $timeEnd . self::$globalSecret);
    }

    /**
     * Get a public key
     *
     * @return string
     */
    public static function getPublicKey()
    {
        if (!isset(self::$publicKeyPath)) {
            throw new \RuntimeException('Path to the authorizer public key is not set');
        }
        
        if(!file_exists (self::$publicKeyPath)) {
            throw new \RuntimeException('Path to public key does not exist');
        }

        $publicKey = file_get_contents(self::$publicKeyPath);
        self::assertIsValidKey('public', $publicKey, self::$publicKeyPath);
        
        return $publicKey;
    }

    /**
     * Get a private key
     *
     * @return string
     */
    protected static function getPrivateKey()
    {
        if (!isset(self::$privateKeyPath)) {
            throw new \RuntimeException('Path to the authorizer private key is not set');
        }
        
        if(!file_exists (self::$privateKeyPath)) {
            throw new \RuntimeException('Path to private key does not exist');
        }

        $privateKey = file_get_contents(self::$privateKeyPath);
        self::assertIsValidKey('private', $privateKey, self::$privateKeyPath);
        
        return $privateKey;
    }
    
    /**
     * Generate a private key
     * 
     * @param array $options
     * @throws RuntimeException
     * @return string
     */
    public static function createPrivateKey($options = []) {
        
        if (!isset(self::$privateKeyPath)) {
            throw new \RuntimeException('Path to the authorizer private key is not set');
        }
        
        if(file_exists (self::$privateKeyPath)) {
            throw new \RuntimeException('Private key already exists');
        }
        
        $config = array(
            "digest_alg" => "sha512",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        
        $config = $options + $config;
        
        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $key);
        self::clearOpenSSLErrors();
        file_put_contents(self::$privateKeyPath, $key);
        return $key;
    }
    
    /**
     * Generate a public based on existing private keyu
     * @throws \RuntimeException
     * @return string
     */
    public static function createPublicKey() {
        if (!isset(self::$publicKeyPath)) {
            throw new \RuntimeException('Path to the authorizer public key is not set');
        }
        
        if(file_exists (self::$publicKeyPath)) {
            throw new \RuntimeException('Public key already exists');
        }
        $privateKey = openssl_get_privatekey(self::getPrivateKey());
        $pubKey = openssl_pkey_get_details($privateKey);
        $key = $pubKey["key"];
        self::clearOpenSSLErrors();
        file_put_contents(self::$publicKeyPath, $key);
        return $key;
    }

    /**
     * Get a public key through a remote url
     * 
     * @param string   $url
     * @param string   $options  Options for the guzzle request
     * @return string
     */
    protected static function downloadSigningKey($url, $options = [])
    {
        $client = new \GuzzleHttp\Client();
        $res = $client->get($url, $options);

        $publicKey = $res->getBody();
        self::assertIsValidKey('public', $publicKey, $url);
        
        return $publicKey;
    }
    
    /**
     * Check if it's a valid public or private key
     *
     * @param string $type  'public' or 'private'     
     * @param string $key
     * @param string $path
     * @throws RuntimeException
     */
    protected static function assertIsValidKey($type, $key, $path)
    {
        if (!preg_match('/^-----BEGIN (RSA |DSA )?' . strtoupper($type) . ' KEY-----/', $key)) {
            throw new \RuntimeException("Invalid $type key: $path");
        }
    }
    
    protected static function clearOpenSSLErrors()
    {
        while($message = openssl_error_string()){ 
            continue;
        }
    }
}
