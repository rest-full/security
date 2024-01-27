<?php

namespace App\Model\Validation;

use Restfull\ORM\Validation\BaseValidation;

/**
 * Description of AppValidation
 * @package App\Model\Validation
 */
class AppValidation extends BaseValidation
{

    /**
     * @return bool
     */
    public function validations()
    {
        $keysRules = array_keys($this->data);
        for ($a = 0; $a < count($keysRules); $a++) {
            $rules = $this->getRules($keysRules[$a]);
            if (in_array('required', $rules) !== false) {
                array_shift($rules);
                $this->required($keysRules[$a]);
                if ($this->check()) {
                    return true;
                }
            }
            switch ($keysRules[$a]) {
                case "email":
                    $this->array($keysRules[$a])->email($keysRules[$a])->equals($keysRules[$a]);
                    break;
                case "numeric":
                    $this->numeric($keysRules[$a]);
                    if (in_array('varchar(14)', $rules) !== false || in_array('varchar(18)', $rules) !== false) {
                        $this->phone($keysRules[$a]);
                    }
                    break;
                case "price":
                    $this->float($keysRules[$a]);
                    break;
                case "date":
                    $this->date($keysRules[$a]);
                    break;
                case "time":
                    $this->time($keysRules[$a]);
                    break;
                case "datetime":
                    $this->date($keysRules[$a])->time($keysRules[$a]);
                    break;
                case "file":
                    $this->url($keysRules[$a])->file($keysRules[$a]);
                    break;
                default:
                    $this->string($keysRules[$a])->alphaNumeric($keysRules[$a])->search($keysRules[$a]);
                    break;
            }
        }
        return $this->check();
    }

}