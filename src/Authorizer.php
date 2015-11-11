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

        if ($checksum !== self::generateChecksum($allowedResource, $timeStart, $timeEnd) return false;

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
    private static function generateChecksum($allowedResource, $timeStart, $timeEnd)
    {
        return hash('sha256', $allowedResource . $_SERVER['HTTP_HOST'] . $timeStart . $timeEnd . self::$globalSecret)
    }

    /**
     * Decrypt an encrypted secret
     * 
     * @param string   $encryptedSecret  An encrypted secret with the format:
     *                                   {{resource}};{{time_from}};{{time_to}};{{hash}}
     * @param string   $privateKeyPath   Path to the private key of the current application
     *
     * @return string  $decryptedSecret  String with the format: {{time_from}};{{time_to}};{{checksum}}
     */
    public static function decrypt($encryptedSecret, $privateKeyPath)
    {
        $privateKey = file_get_contents($privateKeyPath);
        openssl_private_decrypt($encryptedSecret, $decryptedSecret, $privateKey);

        return $decryptedSecret;
    }

    /**
     * Get a public key through a remote url
     * 
     * @param string   $url
     * @param string   $options  Options for the guzzle request
     *
     * @return string
     */
    private static function downloadPublicKey($url, $options = [])
    {
        $client = new GuzzleHttp\Client();
        $res = $client->get($url, $options);

        return (string)$res->getBody();
    }
}
