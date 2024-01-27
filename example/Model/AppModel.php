<?php

namespace App\Model;

use Restfull\Error\Exceptions;
use Restfull\ORM\BaseTable;

/**
 * Description of AppModel
 * @package App\Model
 */
class AppModel extends BaseTable
{

    /**
     * @param array $tables
     * @param array $datas
     * @return AppModel
     * @throws Exceptions
     */
    public function tableRepository(array $tables, array $datas = []): AppModel
    {
        $join = false;
        $registories = $this->http($this->tableRegistory->http);
        $this->assembly(count($tables['main']) == 1 ? 'single' : 'several');
        for ($a = 0; $a < count($tables['main']); $a++) {
            $nameTable = $tables['main'][$a]['table'];
            $registories = $this->tableRegistory->registory(
                    (isset($tables['main'][$a]['alias']) ? $nameTable . ' as ' . $tables['main'][$a]['alias'] : $nameTable)
            )->entityColumns($nameTable);
            $registories->connectColumnNameWithTableName = true;
            if (isset($tables['join'][$nameTable])) {
                for ($b = 0; $b < count($tables['join'][$nameTable]); $b++) {
                    if (count($tables['join'][$nameTable][$b]) > 0) {
                        $nameJoin = $tables['join'][$nameTable][$b]['table'];
                        $registories->registory(
                                (isset($tables['join'][$nameTable][$b]['alias']) ? $nameJoin . ' as ' . $tables['join'][$nameTable][$b]['alias'] : $nameJoin),
                                'join'
                        )->entityColumns($nameJoin);
                    }
                }
            }
        }
        $this->tableRegistory = $registories;
        if (count($datas) > 0) {
            $this->dataQuery($datas);
        }
        return $this;
    }
}
