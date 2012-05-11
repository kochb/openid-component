<?php
App::uses('BaseAuthenticate', 'Controller/Component/Auth');
App::uses('OpenidComponent', 'Controller/Component');

/**
 * OpenID Authenticate
 * 
 * This custom authenticate object enables you to drop openid authentication
 * into your application with ease.
 * 
 * To determine which user is attempting to log in, this Authentication handler
 * utilizes a findByOpenid() method on the user model.
 *   - When not defined, Cake's default findBy* methodology will kick in. 
 *   - When defined, you will be able to manually perform a search for a user
 *     with a matching openid.
 * 
 * It is advised that you implement a findByOpenid() method for the sake of
 * clarity, and because your openid implementation will likely be more complex
 * than this.
 * 
 * @author Brad Koch <bradkoch2007@gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.php The MIT License
 */
class OpenidAuthenticate extends BaseAuthenticate {

    public $settings = array(
        'fields' => array(
            'openid' => 'openid'
		),
		'userModel' => 'User',
		'scope' => array()
	);

    private $User = null;
    private $Openid = null;

    /**
     * Constructor
     *
     * @param ComponentCollection $collection The Component collection used on this request.
     * @param array $settings Array of settings to use.
     */
	public function __construct(ComponentCollection $collection, $settings) {
        parent::__construct($collection, $settings);

        $this->User = ClassRegistry::init($this->settings['userModel']);
        $this->Openid = $collection->load('Openid.Openid');
    }

    /**
     * Authenticate
     * 
     * Runs the authentication process.
     * 
     * @author Brad Koch <bradkoch2007@gmail.com>
     */
    public function authenticate(CakeRequest $request, CakeResponse $response) {
        $fields = $this->settings['fields'];
        $realm = 'http://'.$_SERVER['HTTP_HOST'];
        $returnTo = $realm . '/users/login';

        if (
            $request->is('post') &&
            (! empty($request->data[$this->settings['userModel']])) &&
            (! empty($request->data[$this->settings['userModel']][$fields['openid']])) &&
            (! $this->Openid->isOpenIDResponse())
        ) {
            // OpenID Step 1 - handle user's request to auth via openid
            $this->Openid->authenticate($request->data[$this->settings['userModel']][$fields['openid']], $returnTo, $realm);
        } elseif ($this->Openid->isOpenIDResponse()) {
            // OpenID Step 2 - see if we recognize this user.
            $response = $this->Openid->getResponse($returnTo);

            if ($response->status == Auth_OpenID_SUCCESS) {
                return $this->_findUserByOpenid($response->identity_url);
            }

            if ($response->status == Auth_OpenID_FAILURE) {
                CakeLog::write(LOG_ERROR, 'OpenID verification for ' . $response->identity_url . ' failed: '.$response->message);
            } elseif ($response->status == Auth_OpenID_CANCEL) {
                CakeLog::write(LOG_ERROR, 'Verification cancelled for ' . $response->identity_url . '.');
            }
        }

        // This is not an openid authentication attempt.
        return false;
    }

/**
 * Find a user record based on an openid url.  This task is subdelegated to the
 * user model.
 *
 * @param string $username The username/identifier.
 * @param string $password The unhashed password.
 * @return Mixed Either false on failure, or an array of user data.
 */
    protected function _findUserByOpenid($openid) {
        $result = $this->User->findByOpenid($openid);
        if (empty($result) || empty($result[$this->settings['userModel']])) {
            return false;
        }

        return $result[$this->settings['userModel']];
    }

}
