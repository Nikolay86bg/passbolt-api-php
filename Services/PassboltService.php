<?php

namespace App\Services;


class PassboltService
{
    /***
     * For more API documentation https://api-reference.passbolt.com/
     */

    /**
     * @var PassboltAuthService
     */
    private $passboltAuth;

    /**
     * @var string
     */
    private $passboltServerUrl;

    /**
     * PassboltService constructor.
     * @param string $passboltServerUrl
     * @param string $passboltPrivateKeyPath
     * @param string $passboltPrivateKyePassphrase
     */
    public function __construct(string $passboltServerUrl, string $passboltPrivateKeyPath, string $passboltPrivateKyePassphrase)
    {
        $this->passboltServerUrl = $passboltServerUrl;

        try {
            if (!extension_loaded('gnupg')) {
                trigger_error('You must enable the gnupg extension.', E_USER_ERROR);
            }
            if (!extension_loaded('curl')) {
                trigger_error('You must enable the curl extension.', E_USER_ERROR);
            }
            $this->passboltAuth = new PassboltAuthService($this->passboltServerUrl, $passboltPrivateKeyPath, $passboltPrivateKyePassphrase);

            $this->passboltAuth->login();
        } catch (\Exception $exception) {
            die($exception->getMessage());
        }
    }

    /**
     * @param string $name
     * @param string $username
     * @param string $description
     * @param string $uri
     * @param string $password
     * @return mixed
     */
    public function createResource(string $name, string $username = '', string $description = '', string $uri = '', string $password)
    {
        $postParams = ([
            'name' => $name,
            'username' => $username,
            'description' => $description,
            'uri' => $uri,
            'secrets' => [[
                'data' => $this->passboltAuth->getEncodedPassword($password)
            ]]
        ]);

        $ch = curl_init($this->passboltServerUrl . '/resources.json?api-version=v2');
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postParams));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_COOKIE, $this->passboltAuth->getCookie(true));
        curl_setopt($ch, CURLINFO_HEADER_OUT, true);
        $extraHeaders = array(
            "X-CSRF-Token: {$this->passboltAuth->csrfToken}",
        );
        curl_setopt($ch, CURLOPT_HTTPHEADER, $extraHeaders);
        $response = curl_exec($ch);
        curl_close($ch);

        return json_decode($response);
    }

    /**
     * @param string $resourceId
     * @param string $password
     * @param string $userId
     * @param string $name
     * @param string $username
     * @param string $description
     * @param string $uri
     * @return mixed
     */
    public function updateResource(string $resourceId, string $password, string $userId, string $name, string $username, string $description, string $uri)
    {
        $postParams = ([
            'name' => $name,
            'username' => $username,
            'description' => $description,
            'uri' => $uri,
            'secrets' => [[
                'user_id' => $userId,
                'data' => $this->passboltAuth->getEncodedPassword($password)
            ]]
        ]);

        $ch = curl_init($this->passboltServerUrl . '/resources/' . $resourceId . '.json');
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postParams));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_COOKIE, $this->passboltAuth->getCookie(true));
        curl_setopt($ch, CURLINFO_HEADER_OUT, true);
        $extraHeaders = array(
            "X-CSRF-Token: {$this->passboltAuth->csrfToken}",
        );
        curl_setopt($ch, CURLOPT_HTTPHEADER, $extraHeaders);
        $response = curl_exec($ch);
        curl_close($ch);

        return json_decode($response);
    }

    /**
     * @return mixed
     */
    public function getResources()
    {
        $ch = curl_init($this->passboltServerUrl . '/resources/.json');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_COOKIE, $this->passboltAuth->getCookie());
        $extraHeaders = array(
            "X-CSRF-Token: {$this->passboltAuth->csrfToken}",
        );
        curl_setopt($ch, CURLOPT_HTTPHEADER, $extraHeaders);
        $response = curl_exec($ch);
        curl_close($ch);

        return json_decode($response);
    }

    /**
     * @param string $resourceId
     * @return mixed
     */
    public function getResource(string $resourceId)
    {
        $ch = curl_init($this->passboltServerUrl . '/resources/' . $resourceId . '.json');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_COOKIE, $this->passboltAuth->getCookie());
        $response = curl_exec($ch);
        curl_close($ch);

        return json_decode($response);
    }

    /**
     * @param string $resourceId
     * @return mixed
     */
    public function getSecret(string $resourceId)
    {
        $ch = curl_init($this->passboltServerUrl . '/secrets/resource/' . $resourceId . '.json');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_COOKIE, $this->passboltAuth->getCookie());
        $response = curl_exec($ch);
        curl_close($ch);

        $secretData = json_decode($response, true)['body']['data'];
        $secret = $this->passboltAuth->getDecodedPassword($secretData);

        return json_decode($secret);
    }

    /**
     * @param string $resourceId
     * @return mixed
     */
    public function deleteResource(string $resourceId)
    {
        $ch = curl_init($this->passboltServerUrl . '/resources/' . $resourceId . '.json');
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLINFO_HEADER_OUT, true);
        curl_setopt($ch, CURLOPT_COOKIE, $this->passboltAuth->getCookie(true));
        $extraHeaders = array(
            "X-CSRF-Token: {$this->passboltAuth->csrfToken}",
        );
        curl_setopt($ch, CURLOPT_HTTPHEADER, $extraHeaders);
        $response = curl_exec($ch);
        curl_close($ch);

        return json_decode($response);
    }
}