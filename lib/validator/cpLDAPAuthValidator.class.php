<?php

class cpLDAPAuthValidator extends sfValidatorBase {
  
  public function configure($options = array(), $messages = array()) {
    $this->addOption('username_field', 'username');
    $this->addOption('password_field', 'password');
    $this->addOption('throw_global_error', false);

    $this->setMessage('invalid', 'The username and/or password is invalid.');
  }

  protected function doClean($values) {
    $username = isset($values[$this->getOption('username_field')]) ? $values[$this->getOption('username_field')] : '';
    cpLDAP::debug ('######## Username: ' . $username);
    $password = isset($values[$this->getOption('password_field')]) ? $values[$this->getOption('password_field')] : '';

    // password is ok?
    cpLDAP::debug ('######## Checking Password...');
    
    $check_password = self::checkPassword($username, $password);
    cpLDAP::debug('check password: ' . $check_password);
    if ($check_password) {
      cpLDAP::debug ('######## Check Password successful...');
      return $values;
    } 
    else {
      cpLDAP::debug ('######## Check Password failed...');
    }

    if ($this->getOption('throw_global_error')) {
      throw new sfValidatorError($this, 'invalid');
    }

    throw new sfValidatorErrorSchema($this, 
                                     array($this->getOption('username_field') => new sfValidatorError($this, 'invalid')));
  }

  protected function checkPassword($username, $password) {
    if ($callable = sfConfig::get('app_cp_ldap_auth_plugin_check_password_callable')) {
      return call_user_func_array($callable, array($username, $password));
    }
    else {
      return cpLdDAP::checkPassword($username, $password);
    }
  }
}

//sfeof
