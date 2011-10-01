<?php

class cpLDAPAuthActions extends sfActions {

  public function executeSignin($request) {

    $user = $this->getUser();
    if ($user->isAuthenticated()) {
      return $this->redirect('@homepage');
    }

     cpLDAP::debugDump($user, 'the user');

    $class = sfConfig::get('app_cp_ldap_auth_signin_form', 'cpLDAPAuthSigninForm');
    $this->form = new $class();

    cpLDAP::debug("########  Request Method = " . $request->getMethod());

    if ($request->isMethod('post')) {
      cpLDAP::debug("########  a login attempt!  signing in (if validation passed) and redirectifying to homepage or wherever");


      $this->form->bind($request->getParameter('signin'));

      if ($this->form->isValid()) {
        cpLDAP::debug("##### signin form is valid");
        $values = $this->form->getValues();
        $this->getUser()->signin($values['username']);

        // always redirect to a URL set in app.yml
        // or to the referer
        // or to the homepage
        $signinUrl = sfConfig::get('app_cp_ldap_auth_plugin_success_signin_url', $user->getReferer('@homepage'));

        return $this->redirect($signinUrl);
      }
      else {
        cpLDAP::debug("##### what??  signin form is NOT valid");
      }	
    }
    else {
      cpLDAP::debug("########  not a POST!  redirecting to signin form");

      if ($this->getRequest()->isXmlHttpRequest()) {
        $this->getResponse()->setHeaderOnly(true);
        $this->getResponse()->setStatusCode(401);

        return sfView::NONE;
      }


      // if we have been forwarded, then the referer is the current URL
      // if not, this is the referer of the current request
      $user->setReferer($this->getContext()->getActionStack()->getSize() > 1 ? $request->getUri() : $request->getReferer());

      if ($this->getModuleName() != ($module = sfConfig::get('sf_login_module'))) {
        return $this->redirect($module.'/'.sfConfig::get('sf_login_action'));
      }

      $this->getResponse()->setStatusCode(401);
    }
  }
  
  public function executeSignout($request) {
    $this->getUser()->signOut();
  
    $signoutUrl = sfConfig::get('app_cp_ldap_auth_plugin_success_signout_url', $request->getReferer());
  
    $this->redirect('' != $signoutUrl ? $signoutUrl : '@homepage');
  }
  
  public function executeSecure($request) {
    $this->getResponse()->setStatusCode(403);
  }
  
}
