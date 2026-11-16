<?php

namespace IMSGlobal\LTI\Tests\unit;

use IMSGlobal\LTI\LTI_Message_Launch;
use IMSGlobal\LTI\LTI_Public_Key_Exception;
use IMSGlobal\LTI\LTI_Registration;
use IMSGlobal\LTI\Tests\unit\helpers\DummyDatabase;
use IMSGlobal\LTI\Tests\unit\helpers\InMemoryCache;
use ReflectionMethod;
use ReflectionProperty;

/**
 * Fetches the key set from PHP's built-in server, which rejects HTTP/1.0 with 426.
 */
class LTI_Message_Launch_Key_Set_Test extends TestBase {
    private static $server;
    private static $baseUrl;

    public static function setUpBeforeClass()
    {
        $port = self::findFreePort();
        self::$baseUrl = "http://127.0.0.1:{$port}";
        $command = escapeshellarg(PHP_BINARY) . " -S 127.0.0.1:{$port} "
            . escapeshellarg(__DIR__ . '/fixtures/key_set_server.php');
        self::$server = proc_open(
            $command,
            [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes
        );

        // Wait up to 5s for the server to accept connections.
        for ($i = 0; $i < 50; $i++) {
            $socket = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.1);
            if ($socket) {
                fclose($socket);
                return;
            }
            usleep(100000);
        }
        self::fail('Built-in PHP server did not start');
    }

    public static function tearDownAfterClass()
    {
        if (is_resource(self::$server)) {
            proc_terminate(self::$server);
            proc_close(self::$server);
        }
    }

    public function testFixtureServerRejectsHttp10()
    {
        // Guard: the fixture must reject HTTP/1.0 for the HTTP/1.1 test to mean anything.
        $context = stream_context_create(['http' => ['protocol_version' => 1.0, 'ignore_errors' => true]]);
        file_get_contents(self::$baseUrl . '/certs', false, $context);
        $this->assertContains('426', $http_response_header[0]);
    }

    public function testFetchKeySetUsesHttp11()
    {
        $keySet = $this->fetchKeySet(self::$baseUrl . '/certs');
        $this->assertSame('test-kid', $keySet['keys'][0]['kid']);
    }

    public function testFetchKeySetFollowsRedirect()
    {
        $keySet = $this->fetchKeySet(self::$baseUrl . '/redirect-to-certs');
        $this->assertSame('test-kid', $keySet['keys'][0]['kid']);
    }

    public function testFetchKeySetRedirectToErrorThrowsWithFinalStatus()
    {
        $this->setExpectedException(LTI_Public_Key_Exception::class, '500');
        $this->fetchKeySet(self::$baseUrl . '/redirect-to-server-error');
    }

    public function testGetPublicKeyReturnsKeyMatchingKid()
    {
        $launch = $this->newLaunch(self::$baseUrl . '/certs', 'test-kid');
        $method = new ReflectionMethod(LTI_Message_Launch::class, 'get_public_key');
        $method->setAccessible(true);
        $this->assertNotEmpty($method->invoke($launch));
    }

    public function testFetchKeySetNon2xxThrowsWithStatus()
    {
        $this->setExpectedException(LTI_Public_Key_Exception::class, '500');
        $this->fetchKeySet(self::$baseUrl . '/server-error');
    }

    public function testFetchKeySetNonJsonThrows()
    {
        $this->setExpectedException(LTI_Public_Key_Exception::class, 'not a JSON key set');
        $this->fetchKeySet(self::$baseUrl . '/not-json');
    }

    public function testFetchKeySetConnectionFailureThrows()
    {
        $this->setExpectedException(LTI_Public_Key_Exception::class, 'Failed to fetch public key');
        $this->fetchKeySet('http://127.0.0.1:' . self::findFreePort() . '/certs');
    }

    private function fetchKeySet($url)
    {
        $method = new ReflectionMethod(LTI_Message_Launch::class, 'fetch_key_set');
        $method->setAccessible(true);
        return $method->invoke($this->newLaunch($url, 'test-kid'), $url);
    }

    private function newLaunch($keySetUrl, $kid)
    {
        $launch = new LTI_Message_Launch(new DummyDatabase(), new InMemoryCache());

        $registration = new ReflectionProperty(LTI_Message_Launch::class, 'registration');
        $registration->setAccessible(true);
        $registration->setValue($launch, LTI_Registration::newInstance()->set_key_set_url($keySetUrl));

        $jwt = new ReflectionProperty(LTI_Message_Launch::class, 'jwt');
        $jwt->setAccessible(true);
        $jwt->setValue($launch, ['header' => ['kid' => $kid], 'body' => []]);

        return $launch;
    }

    private static function findFreePort()
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $name = stream_socket_get_name($socket, false);
        fclose($socket);
        return (int) substr($name, strrpos($name, ':') + 1);
    }
}
