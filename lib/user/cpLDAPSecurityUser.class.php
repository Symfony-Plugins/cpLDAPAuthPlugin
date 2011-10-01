<?php
class cpLDAPSecurityUser extends sfBasicSecurityUser {
  
  public function signin($username) {
    $this->setAttribute('username', $username, 'cpLDAPSecurityUser');
    $this->setAuthenticated(true);
    $this->clearCredentials();
  }
  
  
  public function signout() {
    $this->clearCredentials();
    $this->setAuthenticated(false);
    /*
     $expiration_age = sfConfig::get('app_sf_guard_plugin_remember_key_expiration_age', 15 * 24 * 3600);
    $remember_cookie = sfConfig::get('app_sf_guard_plugin_remember_cookie_name', 'sfRemember');
    sfContext::getInstance()->getResponse()->setCookie($remember_cookie, '', time() - $expiration_age);
    */
  }
  
  public function getUsername() {
    return $this->getAttribute('username', null, 'cpLDAPSecurityUser');
  }
  
  /**
   * Returns the referer uri.
   *
   * @param string $default The default uri to return
   *
   * @return string $referer The referer
   */
  public function getReferer($default)
  {
    $referer = $this->getAttribute('referer', $default);
    $this->getAttributeHolder()->remove('referer');

    return $referer;
  }

  /**
   * Sets the referer.
   *
   * @param string $referer
   */
  public function setReferer($referer)
  {
    if (!$this->hasAttribute('referer'))
    {
      $this->setAttribute('referer', $referer);
    }
  }

  /**
   * Returns whether or not the user is anonymous.
   *
   * @return boolean
   */
  public function isAnonymous() {
    return !$this->isAuthenticated();
  }

}
