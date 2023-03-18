<?php

namespace App\Model\Entity;

use Restfull\ORM\Entity\Entity;
use Restfull\ORM\TableRegistry;

/**
 * Class AppEntity
 * @package App\Model\Entity
 */
class AppEntity extends Entity
{

    /**
     * AppEntity constructor.
     * @param TableRegistry $table
     * @param array $config
     */
    public function __construct(TableRegistry $table, array $config = [])
    {
        if (count($config) > 0) {
            $type = $config['type'];
            unset($config['type']);
            $this->config($type, $config);
            $this->repository($table);
            $this->entity();
            return $this;
        }
        return $this;
    }

    /**
     * @param TableRegistry $tableRegistry
     * @return AppEntity
     */
    public function repository(TableRegistry $tableRegistry): AppEntity
    {
        $this->repository = $tableRegistry;
        return $this;
    }
}