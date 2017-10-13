<?php
use Codeception\TestCase\Test;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use LegalThings\Authorizer;

class AuthorizerTest extends Test
{
   /**
    * @var UnitTester
    */
    protected $tester;
    
    const KEYS_DIR = "tests/keys";

    // executed before each test
    protected function _before()
    {
        if(file_exists(self::KEYS_DIR)) {
            rmdir(self::KEYS_DIR);
        }
        mkdir(self::KEYS_DIR, 0700, TRUE);
        Authorizer::$globalSecret = "testsecret";
        Authorizer::$privateKeyPath = self::KEYS_DIR . "/private_key.pem";
        Authorizer::$publicKeyPath = self::KEYS_DIR . "/public_key.pem";
    }

    // executed after each test
    protected function _after()
    {
        if(file_exists(self::KEYS_DIR . "/private_key.pem")) {
            unlink(self::KEYS_DIR . "/private_key.pem");
        }
        if(file_exists(self::KEYS_DIR . "/public_key.pem")) {
            unlink(self::KEYS_DIR . "/public_key.pem");
        }
        rmdir(self::KEYS_DIR);
    }
    
    public function testGeneratePrivateKey() {
        
        $privateKey = Authorizer::createPrivateKey();
        $this->assertTrue($this->checkKey("private", $privateKey));
    }
    
    public function testGeneratePrivateAndPublicKey() {
        
        $privateKey = Authorizer::createPrivateKey();
        $this->assertTrue($this->checkKey("private", $privateKey));
        
        $publicKey = Authorizer::createPublicKey();
        $this->assertTrue($this->checkKey("public", $publicKey));
    }
    
    public function testGetPublicKey() {
        
        Authorizer::$privateKeyPath = "tests/_data/private_key.pem";
        Authorizer::$publicKeyPath = "tests/_data/public_key.pem";
        
        $publicKey = Authorizer::getPublicKey();
        $this->assertTrue($this->checkKey("public", $publicKey));
    }
    
    public function testSignDecryptingAndVerifying() {
        
        Authorizer::$privateKeyPath = "tests/_data/private_key.pem";
        Authorizer::$publicKeyPath = "tests/_data/public_key.pem";
        $_SERVER['HTTP_HOST'] = "example.com";
        
        $resource = "secret resource";
        $startTime = time();
        $endTime = $startTime + 500;
        
        $mock = new MockHandler([
            new Response(200, [], Authorizer::getPublicKey()),
            new Response(200, [], Authorizer::getPublicKey())
        ]);
        $handler = HandlerStack::create($mock);
        $encryptedSecret = Authorizer::sign($resource, "http://example.com/public_key.pem;$startTime;$endTime", $handler);
        
        $decrypted = Authorizer::decrypt($encryptedSecret);
        
        $values = explode(";", $decrypted);
        $this->assertEquals($startTime, $values[0]);
        $this->assertEquals($endTime, $values[1]);
        
        $this->assertTrue(Authorizer::verify($resource, $decrypted));
    }
    
    protected function checkKey($type, $key) {
        if (!preg_match('/^-----BEGIN (RSA |DSA )?' . strtoupper($type) . ' KEY-----/', $key)) {
            return false;
        }
        
        return true;
    }
}
?>