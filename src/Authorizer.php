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
     * @param string  $resource
     * @param string  $authzgen  String with the format: {{certificate_url}};{{time_from}};{{time_to}}
     *                           Time restrictions are unix timestamps, but may be omitted 
     */
    public static function sign($resource, $authzgen)
    {
        if (!isset(self::$globalSecret)) trigger_error('$globalSecret is not set', E_USER_WARNING);

        list($cerfiticateUrl, $timeStart, $timeEnd) = explode(';', $authzgen) + [null, null, null];

        $publicKey = self::downloadPublicKey($cerfiticateUrl);

        $resourceSecret = join(';', [
            $resource,
            $timeStart,
            $timeEnd,
            hash('sha256', $resource . $_SERVER['HTTP_HOST'] . $timeStart . $timeEnd . self::$globalSecret)
        ]);

        openssl_public_encrypt($resourceSecret, $encryptedSecret, $publicKey);

        return $encryptedSecret;
    }

    /**
     * Verify if a resource may be accessed by the client by decrypting a secret
     * 
     * @param string  $allowedResource
     * @param string  $authz            An encrypted secret with the format:
     *                                  {{resource}};{{time_from}};{{time_to}};{{hash}}
     * @param string  $privateKeyPath   Path to the private key of the current application
     */
    public static function verify($allowedResource, $authz, $privateKeyPath)
    {
        $currentTime = time();
        $privateKey = file_get_contents($privateKeyPath);

        openssl_private_decrypt($authz, $decryptedSecret, $privateKey);
        list($resource, $timeStart, $timeEnd) = explode(';', $decryptedSecret) + [null, null, null];

        $timeStart = strlen($timeStart) > 0 ? (int)$timeStart : ($currentTime - 1);
        $timeEnd = strlen($timeEnd) > 0 ? (int)$timeEnd : ($currentTime + 1);

        if ($resource !== $allowedResource) return false;
        if ($currentTime < $timeStart || $currentTime > $timeEnd) return false;

        return true;
    }

    /**
     * Get a public key through a remote url
     * 
     * @param string  $url
     * @param string  $options  Options for the guzzle request
     */
    private static function downloadPublicKey($url, $options = [])
    {
        $client = new GuzzleHttp\Client();
        $res = $client->get($url, $options);

        return (string)$res->getBody();
    }
}
