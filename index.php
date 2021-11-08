<?php
namespace App;

use App\Services\PassboltService;

require(__DIR__.'\Services\PassboltService.php');

$passbolt = new PassboltService('passboltServerUrl',__DIR__.'\config\passbolt_private.txt','passboltPrivateKeyPassphrase');

//Create resource
$response = $passbolt->createResource('Name','Username', 'Description','Uri','Password');
print_r($response);

//Get resource info
$response = $passbolt->getResource('resourceId');
print_r($response);

//Update resource
$response = $passbolt->updateResource('resourceId','newPassword', 'userId', 'Name','Username','Description','Uri');
print_r($response);

//Delete resource
$response = $passbolt->deleteResource('resourceId');
print_r($response);

//Get only resource password
$response = $passbolt->getSecret('resourceId');
print_r($response);

//Get all resources example
$resources = $passbolt->getResources();
print_r($resources);