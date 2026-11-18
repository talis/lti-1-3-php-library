<?php

namespace IMSGlobal\LTI\Tests\unit;

use Firebase\JWT\JWT;
use IMSGlobal\LTI\Cookie;
use IMSGlobal\LTI\LTI_Message_Launch;
use IMSGlobal\LTI\LTI_Public_Key_Exception;
use IMSGlobal\LTI\Tests\unit\helpers\DummyDatabase;
use IMSGlobal\LTI\Tests\unit\helpers\InMemoryCache;

/**
 * Validates launches whose key set is served by a stub platform that rejects HTTP/1.0 with 426.
 */
class LTI_Message_Launch_Key_Set_Test extends TestBase {
    private static $server;
    private static $baseUrl;

    public static function setUpBeforeClass()
    {
        $port = self::findFreePort();
        self::$baseUrl = "http://127.0.0.1:{$port}";
        $command = escapeshellarg(PHP_BINARY) . " -S 127.0.0.1:{$port} "
            . escapeshellarg(__DIR__ . '/helpers/key_set_server.php');
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

    public function testStubServerRejectsHttp10()
    {
        // Guard: the stub must reject HTTP/1.0 for the HTTP/1.1 tests to mean anything.
        $context = stream_context_create(['http' => ['protocol_version' => 1.0, 'ignore_errors' => true]]);
        file_get_contents(self::$baseUrl . '/certs', false, $context);
        $this->assertContains('426', $http_response_header[0]);
    }

    public function testValidateFetchesKeySetOverHttp11()
    {
        $launch = $this->validateLaunch(self::$baseUrl . '/certs');
        $this->assertSame('aaa', $launch->get_launch_data()['iss']);
    }

    public function testValidateFollowsKeySetRedirect()
    {
        $launch = $this->validateLaunch(self::$baseUrl . '/redirect-to-certs');
        $this->assertSame('aaa', $launch->get_launch_data()['iss']);
    }

    public function testValidateThrowsWithStatusWhenKeySetServerErrors()
    {
        $this->setExpectedException(LTI_Public_Key_Exception::class, '500');
        $this->validateLaunch(self::$baseUrl . '/server-error');
    }

    public function testValidateThrowsWithFinalStatusWhenKeySetRedirectsToError()
    {
        $this->setExpectedException(LTI_Public_Key_Exception::class, '500');
        $this->validateLaunch(self::$baseUrl . '/redirect-to-server-error');
    }

    public function testValidateThrowsWhenKeySetIsNotJson()
    {
        $this->setExpectedException(LTI_Public_Key_Exception::class, 'not a JSON key set');
        $this->validateLaunch(self::$baseUrl . '/not-json');
    }

    public function testValidateThrowsWhenKeySetServerIsUnreachable()
    {
        $this->setExpectedException(LTI_Public_Key_Exception::class, 'Failed to fetch public key');
        $this->validateLaunch('http://127.0.0.1:' . self::findFreePort() . '/certs');
    }

    /**
     * Validates a resource link launch signed with fixtures/private.key, whose registration
     * points at the given key set URL.
     */
    private function validateLaunch($keySetUrl)
    {
        $payload = json_decode(file_get_contents(__DIR__ . '/fixtures/jwts/lti_message_launch_tests_jwt.json'), true);
        $payload['https://purl.imsglobal.org/spec/lti/claim/message_type'] = 'LtiResourceLinkRequest';
        $idToken = JWT::encode($payload, file_get_contents(__DIR__ . '/fixtures/private.key'), 'RS256', 'test-kid');

        $state = uniqid();
        /** @var Cookie|\PHPUnit_Framework_MockObject_MockObject $cookie */
        $cookie = $this->getMockBuilder(Cookie::class)
            ->setMethods(['get_cookie'])
            ->getMock();
        $cookie->method('get_cookie')->with('lti1p3_' . $state)->willReturn($state);

        $database = new class($keySetUrl) extends DummyDatabase {
            private $keySetUrl;

            public function __construct($keySetUrl)
            {
                $this->keySetUrl = $keySetUrl;
            }

            public function find_registration_by_issuer($iss, $clientId = null)
            {
                $registration = parent::find_registration_by_issuer($iss, $clientId);
                return $registration ? $registration->set_key_set_url($this->keySetUrl) : null;
            }
        };

        return LTI_Message_Launch::newInstance($database, new InMemoryCache(), $cookie)
            ->validate(['state' => $state, 'id_token' => $idToken]);
    }

    private static function findFreePort()
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $name = stream_socket_get_name($socket, false);
        fclose($socket);
        return (int) substr($name, strrpos($name, ':') + 1);
    }
}
