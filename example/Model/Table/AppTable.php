<?php

namespace App\Model\Table;

use Restfull\Error\Exceptions;
use Restfull\ORM\BaseTable;

/**
 * Description of AppTable
 * @package App\Model\Table
 */
class AppTable extends BaseTable
{
    /**
     * @var array
     */
    private $attributes = [];

    /**
     * @var array
     */
    private $columnType = [];

    /**
     * @var array
     */
    private $name = [];

    /**
     * @var array
     */
    private $data = [];

    /**
     *
     */
    public function __construct()
    {
        $name = explode(', ', $this->tableRegistory->name);
        for ($a = 0; $a < count($name); $a++) {
            foreach ($this->tableRegistory->columns[$name[$a]] as $values) {
                $this->attributes[$name[$a]][] = $values['name'];
                $this->columnType[$name[$a]][] = $values['type'];
            }
        }
        $this->name = $name;
        return $this;
    }

    /**
     * @param array $datas
     * @return array
     * @throws Exceptions
     */
    public function attributes(array $datas): array
    {
        $newDatas = $datas;
        foreach (['nested', 'union'] as $key) {
            if (isset($newDatas[$key])) {
                unset($newDatas[$key]);
            }
        }
        for ($a = 0; $a < count($newDatas); $a++) {
            $this->data[$newDatas[$a]['table']][] = $this->thereIsThisColumnForCreateOrChangeTheTable(
                    $newDatas[$a]['fields'],
                    $this->attributes[$newDatas[$a]['table']],
                    $newDatas[$a]['table']
            );
        }
        return $datas;
    }

    /**
     * @return $this
     */
    public function convert()
    {
        for ($a = 0; $a < count($this->name); $a++) {
            $name = $this->name[$a];
            foreach ($this->columnType[$name] as $key => $value) {
                if (in_array(
                                $value,
                                $this->instance->getMethods(
                                        $this->instance->namespaceClass(
                                                '%s' . DS_REVERSE . '%s' . DS_REVERSE . '%s' . DS_REVERSE . '%s',
                                                [substr(ROOT_APP, 0, -1), MVC[2]['app'], SUBMVC[2][1], $name]
                                        )
                                )
                        ) !== false) {
                    $this->{$value}($this->data[$name][$key]);
                }
            }
        }
        return $this;
    }
}