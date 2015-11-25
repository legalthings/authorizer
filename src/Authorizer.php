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
     * Sign a resource, granting access to a specific client
     * 
     * @param string   $allowedResource
     * @param string   $authzgen         String with the format: {{certificate_url}};{{time_from}};{{time_to}}
     *                                   Time restrictions are unix timestamps, but may be omitted 
     * @return string  $encryptedSecret
     */
    public static function sign($allowedResource, $authzgen)
    {
        if (!isset(self::$globalSecret)) trigger_error('$globalSecret is not set', E_USER_WARNING);

        list($cerfiticateUrl, $timeStart, $timeEnd) = explode(';', $authzgen) + [null, null, null];

        $publicKey = self::downloadPublicKey($cerfiticateUrl);

        $resourceSecret = join(';', [
            $timeStart,
            $timeEnd,
            self::generateChecksum($allowedResource, $timeStart, $timeEnd)
        ]);

        openssl_public_encrypt($resourceSecret, $encryptedSecret, $publicKey);

        return $encryptedSecret;
    }

    /**
     * Decrypt an encrypted secret
     * 
     * @param string   $encryptedSecret  An encrypted secret with the format:
     *                                   {{resource}};{{time_from}};{{time_to}};{{hash}}
     *
     * @return string  $decryptedSecret  String with the format: {{time_from}};{{time_to}};{{checksum}}
     */
    public static function decrypt($encryptedSecret)
    {
        openssl_private_decrypt($encryptedSecret, $decryptedSecret, self::getPrivateKey());

        return $decryptedSecret;
    }

    /**
     * Verify if a resource may be accessed by the client
     * 
     * @param string    $allowedResource
     * @param string    $decryptedSecret  can be retrieved with static::decrypt()
     *
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
     *
     * @return string
     */
    protected static function generateChecksum($allowedResource, $timeStart, $timeEnd)
    {
        return hash('sha256', $allowedResource . $_SERVER['HTTP_HOST'] . $timeStart . $timeEnd . self::$globalSecret);
    }

    /**
     * Get a private key
     *
     * @return string
     */
    protected static function getPrivateKey()
    {
        if (!isset(self::$privateKeyPath)) trigger_error('$privateKeyPath is not set', E_USER_WARNING);

        $privateKey = file_get_contents(self::$privateKeyPath);

        return $privateKey;
    }

    /**
     * Get a public key through a remote url
     * 
     * @param string   $url
     * @param string   $options  Options for the guzzle request
     *
     * @return string
     */
    protected static function downloadPublicKey($url, $options = [])
    {
        $client = new \GuzzleHttp\Client();
        $res = $client->get($url, $options);

        return (string)$res->getBody();
    }
}
