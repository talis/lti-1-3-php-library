<?php

namespace IMSGlobal\LTI\Tests\unit;

use IMSGlobal\LTI\Database;
use IMSGlobal\LTI\LTI_Registration;
use IMSGlobal\LTI\LTI_Deployment;

class DummyDatabase implements Database {
    public function find_registration_by_issuer($iss, $clientId = null)
    {
        $privateKeyFileContents = file_get_contents(dirname(__FILE__) . '/fixtures/private.key');
        $registrationDBFile = file_get_contents(dirname(__FILE__) . '/fixtures/registration_db.json');
        $details = null;
        if ($registrationDBFile) {
            $registrations = json_decode($registrationDBFile, true);
            foreach ($registrations as $registrationDetails) {
                if ($registrationDetails['issuer'] === $iss) {
                    if (empty($clientId) || $registrationDetails['client_id'] === $clientId) {
                        $details = $registrationDetails;
                        break;
                    }
                }
            }
            if (!empty($details)) {
                if (empty($clientId)) {
                    $clientId = $details['client_id'];                    
                }

                $registration = LTI_Registration::newInstance()
                    ->set_auth_login_url($details['auth_login_url'])
                    ->set_auth_token_url($details['auth_token_url'])
                    ->set_key_set_url($details['key_set_url'])
                    ->set_kid("key_{$iss}_{$clientId}")
                    ->set_tool_private_key($privateKeyFileContents);                
                

                $registration->set_client_id($clientId);
                return $registration;
            }
        }

        throw new \Exception('Cannot find issuer details in registrations file');
    }

    public function find_deployment($iss, $deployment_id)
    {
        return LTI_Deployment::newInstance()->set_deployment_id($deployment_id);
    }
}
