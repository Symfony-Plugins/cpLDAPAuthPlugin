<?php


class cpLDAPAuthSigninForm extends BaseForm {
  /**
   * @see sfForm
   */
  public function setup() {
    $this->setWidgets(array(
      'username' => new sfWidgetFormInputText(),
      'password' => new sfWidgetFormInputPassword(array('type' => 'password')),
      'remember' => new sfWidgetFormInputCheckbox(),
    ));

    $this->setValidators(array(
      'username' => new sfValidatorString(),
      'password' => new sfValidatorString(),
      'remember' => new sfValidatorBoolean(),
    ));

    $this->validatorSchema->setPostValidator(new cpLDAPAuthValidator());

    $this->widgetSchema->setNameFormat('signin[%s]');

    parent::setup();
  }
}