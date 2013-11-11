<?php
/**
 * VKontakte strategy for Opauth
 * based on http://vk.com/developers.php?oid=-17680044&p=Authorizing_Sites
 */

class VKontakteStrategy extends OpauthStrategy{

	/**
	 * Compulsory config keys, listed as unassociative arrays
	 */
	public $expects = array('app_id', 'app_secret');

	/**
	 * Optional config keys with respective default values, listed as associative arrays
	 */
	public $defaults = array(
		'redirect_uri' => '{complete_url_to_strategy}int_callback',
		'scope' => 'friends',  // Check http://vk.com/developers.php?oid=-17680044&p=Application_Access_Rights
	);

	/**
	 * Auth request
	 */
	public function request(){
		$url = 'https://oauth.vk.com/authorize';
		$params = array(
			'client_id' => $this->strategy['app_id'],
			'scope' => $this->strategy['scope'],
			'redirect_uri' => $this->strategy['redirect_uri'],
			'response_type' => 'code',
		);

		$this->clientGet($url, $params);
	}

	/**
	 * Internal callback to get the code and request que authorization token, after VKontakte's OAuth
	 */
	public function int_callback(){
		if (array_key_exists('code', $_GET) && !empty($_GET['code'])){
			$url = 'https://oauth.vk.com/access_token'; //DGB 2012-11-06 Notice VK documentation is wrong, because they DO require HTTPS
			$params = array(
				'client_id' =>$this->strategy['app_id'],
				'client_secret' => $this->strategy['app_secret'],
				'code' => $_GET['code'],
				'redirect_uri'=> $this->strategy['redirect_uri'],
			);
			$response = $this->serverGet($url,$params,false,$headers);
			if (empty($response)){
				$error = array(
					'code' => 'Get access token error',
					'message' => 'Failed when attempting to get access token',
					'raw' => array(
						'headers' => $headers
					)
				);

				$this->errorCallback($error);
			}
			$results=json_decode($response,true);

            $this->processToken($results['access_token'], $results['user_id'], $results['expires_in']);

				 // If the data doesn't seem to be written to the session, it is probably because your sessions are
				// stored in the database and your session table is not encoded in UTF8.
				// The following lines will jump over the security but will allow you to use
				 // the plugin without utf8 support in the database.

         // $completeUrl = Configure::read('Opauth._cakephp_plugin_complete_url');
         // if (empty($completeUrl)) $completeUrl = Router::url('/opauth-complete');
         // $CakeRequest = new CakeRequest('/opauth-complete');
         // $data['auth'] = $this->auth;
         // $CakeRequest->data = $data;
         // $Dispatcher = new Dispatcher();
         // $Dispatcher->dispatch( $CakeRequest, new CakeResponse() );
         // exit();
		}
		else
		{
			$error = array(
				'code' => isset($_GET['error'])?$_GET['error']:0,
				'message' => isset($_GET['error_description'])?$_GET['error_description']:'',
				'raw' => $_GET
			);

			$this->errorCallback($error);
		}
	}

    public function processToken($accessToken, $userId, $tokenExpires = 0)
    {
        $userResponse = $this->getUser($accessToken, $userId);

        $vkUser     = $userResponse['response']['0'];
        $this->auth = array(
            'provider'    => 'VKontakte',
            'uid'         => $vkUser['uid'],
            'info'        => array(),
            'credentials' => array(
                'token'   => $accessToken,
                'expires' => date('c', time() + $tokenExpires)
            ),
            'raw'         => $vkUser
        );

        if (!empty($vkUser['first_name'])) {
            $this->auth['info']['name'] = $vkUser['first_name'];
        }
        if (!empty($vkUser['screen_name'])) {
            $this->auth['info']['nickname'] = $vkUser['screen_name'];
        }
        if (!empty($vkUser['sex']) and ($vkUser['sex'] != '0')) {
            $this->auth['info']['gender'] = ($vkUser['sex'] == '1') ? 'female' : 'male';
        }
        if (!empty($vkUser['photo_big'])) {
            $this->auth['info']['image'] = $vkUser['photo_big'];
        }

        $this->callback();
    }

    private function getUser($access_token, $uid)
    {
        $fields = 'uid, first_name, last_name, nickname, screen_name, sex, bdate, photo, photo_medium, photo_big, rate, contacts';
        $vkUser = $this->serverget(
            'https://api.vk.com/method/users.get',
            array('access_token' => $access_token, 'uid' => $uid, 'fields' => $fields),
            array(),
            $headers
        );
        if (!empty($vkUser)) {
            return json_decode($vkUser, true);
        } else {
            $error = array(
                'code'    => 'Get User error',
                'message' => 'Failed when attempting to query for user information',
                'raw'     => array(
                    'access_token' => $access_token,
                    'headers'      => $headers
                )
            );
            $this->errorCallback($error);
        }
    }
}
