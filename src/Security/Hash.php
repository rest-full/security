<?php

namespace Restfull\Security;

use App\Model\AppModel;
use Restfull\Authentication\Auth;
use Restfull\Error\Exceptions;
use Restfull\Http\Request;
use Restfull\Http\Response;

/**
 *
 */
class Hash
{

    /**
     * @var string
     */
    public $salt = '';

    /**
     * @var string
     */
    private $decripting = '0';

    /**
     * @var int
     */
    private $numberSalt = 32;

    /**
     * @var array
     */
    private $keyEncrypt = ['key' => 'd5cf705155810666f7f3', 'iv' => 'TkRUY3ExMEVuVGpi', 'level' => 0];

    /**
     * @var auth
     */
    private $auth;

    /**
     * @var array
     */
    private $http = [];

    /**
     * @var string
     */
    private $hash = '';

    /**
     * @var AppModel
     */
    private $table;

    /**
     * @var bool
     */
    private $alfanumerico = true;

    /**
     * @var bool
     */
    private $changeKeyEncrypt = true;

    /**
     * @var int
     */
    private $assettoencryption = 5;

    /**
     * @param Auth $auth
     * @param int $number
     * @param string $salt
     */
    public function __construct(Auth $auth, int $number, string $salt)
    {
        $this->auth = $auth;
        if ($this->numberSalt != $number) {
            $this->numberSalt = $number;
        }
        $this->salt = $salt;
        return $this;
    }

    /**
     * @return int
     */
    public function levelEncrypt(): int
    {
        return $this->keyEncrypt['level'];
    }

    /**
     * @param int $level
     *
     * @return $this
     */
    public function config(
        int  $level,
        bool $changeablePassword = false,
        bool $swapKeyEcrypt = false,
        int  $assetEncrypt = 5
    ): Hash
    {
        if ($this->keyEncrypt['level'] != $level) {
            $this->keyEncrypt['level'] = $level;
            if (!$this->auth->check('hash')) {
                $this->auth->write('hash', ['level' => $level]);
            }
        }
        if ($changeablePassword) {
            $this->alfanumerico = !$this->alfanumerico;
        }
        if ($swapKeyEcrypt) {
            $this->changeKeyEncrypt = !$this->changeKeyEncrypt;
            $this->keyEncrypt = [
                'key' => 'd5cf705155810666f7f3',
                'iv' => 'TkRUY3ExMEVuVGpi',
                'level' => $this->keyEncrypt['level']
            ];
        }
        if ($assetEncrypt != $this->assettoencryption) {
            $this->assettoencryption = $assetEncrypt;
        }
        return $this;
    }

    /**
     * @param Request|null $request
     * @param Response|null $response
     *
     * @return $this
     */
    public function http(
        Request  $request = null,
        Response $response = null
    ): Hash
    {
        $this->http = ['request' => $request, 'response' => $response];
        $this->table = (new AppModel())->http($this->http)->tableRepository(
            [
                'main' => [['table' => 'securities']],
                'join' => ['securities' => [['table' => 'assetstoencryption']]]
            ],
            ['datas' => []]
        );
        return $this;
    }

    /**
     * @param string $path
     *
     * @return string
     */
    public function encrypt(string $path, bool $linkInternalWithExternalAccess = false): string
    {
        $this->decripting = '0';
        if ($this->keyEncrypt['level'] != 0) {
            $this->decripting = '1';
            if ($this->alfanumerico) {
                $caracters = 'abcdefghijklmnopqrstuvwxyz0123456789';
                $crypt = '';
                for ($a = 0; $a < strlen($path); $a++) {
                    $alfanumeric = $caracters[rand(1, 35)];
                    $crypt .= stripos($crypt, $alfanumeric) !== false ? strtoupper(
                        $alfanumeric
                    ) : $alfanumeric;
                    $crypt .= $path[$a];
                }
            } else {
                $crypt = $path;
            }
            if ($this->keyEncrypt['level'] >= 2) {
                $this->assetsToEmcrypt(
                    [
                        'general' => $this->http['request']->encryptKeys['general'],
                        'internal' => $this->http['request']->encryptKeys['internal'],
                        'internalwithexternalaccess' => $linkInternalWithExternalAccess
                            ? 'verdadeiro' : 'falso'
                    ]
                );
                if ($this->changeKeyEncrypt) {
                    $this->opensslKeys(
                        [
                            'decrypting' => $this->decripting,
                            'level' => $this->keyEncrypt['level']
                        ]
                    );
                }
                $crypt = openssl_encrypt($crypt, 'AES-128-CBC', $this->keyEncrypt['key'], 0, $this->keyEncrypt['iv']);
                $crypt = str_replace(DS, '_', str_replace('+', '|', $crypt));
                if ($this->keyEncrypt['level'] == 3) {
                    $crypt = str_replace(DS, '_', base64_encode($crypt));
                    $crypt = stripos($crypt, '=')
                        ? substr($crypt, 0, stripos($crypt, '=')) . '-'
                        . implode('', [
                            $this->http['request']->encryptKeys['general']
                            == 'verdadeiro' ? 1 : 0,
                            $this->http['request']->encryptKeys['internal']
                            == 'verdadeiro' ? 1 : 0,
                            $this->http['request']->encryptKeys['internalwithexternalaccess']
                            == 'verdadeiro' ? 1 : 0,
                        ])
                        : $crypt . '-' . implode('', [
                            $this->http['request']->encryptKeys['general']
                            == 'verdadeiro' ? 1 : 0,
                            $this->http['request']->encryptKeys['internal']
                            == 'verdadeiro' ? 1 : 0,
                            $this->http['request']->encryptKeys['internalwithexternalaccess']
                            == 'verdadeiro' ? 1 : 0,
                        ]);
                }
                return $crypt;
            }
            return $crypt;
        }
        return $path;
    }

    /**
     * @param array $assets
     *
     * @return bool
     * @throws Exceptions
     */
    private function assetsToEmcrypt(array $assets = []): Hash
    {
        $options['join'] = [
            [
                'table' => 'assetstoencryption',
                'type' => 'inner',
                'conditions' => 'assetstoencryption.id = securities.idAssetToEncryption'
            ]
        ];
        $this->table->typeQuery = 'count';
        $options['fields'] = ['count(securities.id) as count'];
        $options['conditions']
            = ['ip & ' => $this->http['request']->server['REMOTE_ADDR']];
        $count = $this->table->dataQuery(
            [$options],
            [['table' => 'securities']]
        )->queryAssembly(['deleteLimit' => [false]])->excuteQuery(
            false,
            $options['fields']
        )->count;
        if ($count > 0) {
            $options['fields'] = [
                'assetstoencryption.general',
                'assetstoencryption.internal',
                'assetstoencryption.internalwithexternalaccess',
                'securities.status',
            ];
            $this->table->typeQuery = 'first';
            $resultSet = $this->table->dataQuery([$options], [['table' => 'securities']])->queryAssembly(
                ['deleteLimit' => [false]]
            )->excuteQuery(false, $options['fields']);
            $this->http['request']->encryptKeys['general'] = $resultSet->general;
            $this->http['request']->encryptKeys['internal'] = $resultSet->internal;
            $this->http['request']->encryptKeys['internalwithexternalaccess'] = $resultSet->internalwithexternalaccess;
            $this->http['request']->encryptKeys['status'] = $resultSet->status;
            return $this;
        }
        $this->http['request']->encryptKeys['general'] = $assets['general'] ?? 'falso';
        $this->http['request']->encryptKeys['internal'] = $assets['internal'] ?? 'verdadeiro';
        $this->http['request']->encryptKeys['internalwithexternalaccess'] = $assets['internalwithexternalaccess'] ?? 'verdadeiro';
        $this->http['request']->encryptKeys['status'] = 'desconnect';
        return $this;
    }

    /**
     * @param array $optionsDefault
     *
     * @return $this
     * @throws Exceptions
     */
    public function opensslKeys(array $optionsDefault = ['decrypting' => 1, 'level' => 3]): Hash
    {
        $this->table->typeQuery = 'count';
        $options['fields'] = ['count(securities.id) as count'];
        $options['conditions']
            = ['ip & ' => $this->http['request']->server['REMOTE_ADDR']];
        if ($this->table->dataQuery([$options], [['table' => 'securities']])->queryAssembly(
                ['deleteLimit' => [false]]
            )->excuteQuery(false, $options['fields'])->count > 0) {
            $options['fields'] = ['securities.id', 'securities.cryption',];
            $this->table->typeQuery = 'first';
            $resultSet = $this->table->dataQuery([$options], [['table' => 'securities']])->queryAssembly(
                ['deleteLimit' => [false]]
            )->excuteQuery(false, $options['fields']);
            $datas = explode(', ', base64_decode($resultSet->cryption));
            if ($this->decripting != $datas[2]) {
                $this->decripting = $datas[2];
            }
            $datas[2] = $datas[3];
            unset($datas[3]);
            if (($this->http['request']->encryptKeys['internalwithexternalaccess'] !== 'falso' && $this->http['request']->encryptKeys['status'] === 'desconnect') || $this->http['request']->encryptKeys['internal'] == 'verdadeiro') {
                if (count($this->keyEncrypt) == 0) {
                    $this->keyEncrypt = ['key' => $datas[0], 'iv' => $datas[1], 'level' => $datas[2]];
                } else {
                    foreach (['key', 'iv', 'level'] as $number => $key) {
                        if (isset($this->keyEncrypt[$key])) {
                            if ($this->keyEncrypt[$key] != $datas[$number]) {
                                $this->keyEncrypt[$key] = $datas[$number];
                            }
                        } else {
                            $this->keyEncrypt[$key] = $datas[$number];
                        }
                    }
                }
            }
            if ($this->keyEncrypt['level'] != $optionsDefault['level'] || $this->decripting != $optionsDefault['decrypting']) {
                $this->table->typeQuery = 'update';
                $datas = [
                    'cryption' => base64_encode(
                        implode(', ', [$this->keyEncrypt['key'], $this->keyEncrypt['iv']]) . ', ' . implode(
                            ', ',
                            ['decrypting' => $optionsDefault['decrypting'], 'level' => $optionsDefault['level']]
                        )
                    )
                ];
                $options = ['fields' => $datas, 'conditions' => ['id & ' => $resultSet->id]];
                $this->table->dataQuery([$options], [['table' => 'securities']])->queryAssembly(
                    ['deleteLimit' => [false]]
                )->excuteQuery(false, $options['fields']);
            }
            return $this;
        }
        if (isset($optionsDefault['level'])) {
            if ($this->keyEncrypt['level'] != $optionsDefault['level']) {
                $this->keyEncrypt['level'] = $optionsDefault['level'];
            }
        }
        return $this->createSecurity(
            ['decrypting' => $optionsDefault['decrypting'], 'level' => $optionsDefault['level']],
            $this->http['request']->encryptKeys['internalwithexternalaccess'] === 'falso'
        );
    }

    /**
     * @return $this
     * @throws Exceptions
     */
    public function createSecurity(array $optionsDefault, bool $createEncrypt = true): Hash
    {
        $this->table->typeQuery = 'create';
        if ($createEncrypt) {
            $this->keyEncrypt['key'] = bin2hex(random_bytes($this->numberSalt));
            $this->keyEncrypt['iv'] = substr(
                base64_encode(crypt(openssl_cipher_iv_length('AES-128-CBC'), $this->salt)),
                0,
                16
            );
        }
        $datas = [
            'idAssetToEncryption' => $this->assettoencryption,
            'ip' => $this->http['request']->server['REMOTE_ADDR'],
            'cryption' => base64_encode(implode(', ', $this->keyEncrypt) . ', ' . implode(', ', $optionsDefault)),
            'status' => 'desconnect'
        ];
        $options = ['fields' => array_keys($datas), 'conditions' => $datas];
        $this->table->dataQuery([$options], [['table' => 'securities']])->queryAssembly(['deleteLimit' => [false]]
        )->excuteQuery(false, $options['fields']);
        return $this;
    }

    /**
     * @param string $crypt
     *
     * @return string
     */
    public function decrypt(string $crypt = '', bool $opensslKeysDatabase = false): string
    {
        if ($this->decripting == '1') {
            if (empty($crypt)) {
                return $this->hash;
            }
            $crypt = substr($crypt, 0, stripos($crypt, '-'));
            $crypt = $this->keyEncrypt['level'] == 3 ? $crypt . '==' : $crypt;
            if ($this->keyEncrypt['level'] == 3) {
                $crypt = base64_decode(base64_encode(preg_replace('@\x{FFFD}@u', '', base64_decode($crypt))));
            }
            if ($this->keyEncrypt['level'] >= 2) {
                if (!$opensslKeysDatabase) {
                    $this->opensslKeys(
                        [
                            'decrypting' => $this->decripting,
                            'level' => $this->keyEncrypt['level']
                        ]
                    );
                }
                $crypt = str_replace('_', DS, str_replace('|', '+', $crypt));
                $crypt = openssl_decrypt($crypt, 'AES-128-CBC', $this->keyEncrypt['key'], 0, $this->keyEncrypt['iv']);
            }
            if ($this->alfanumerico) {
                $path = '';
                for ($a = 1; $a < strlen($crypt); $a = $a + 2) {
                    $path .= $crypt[$a];
                }
                return $path;
            }
            return $crypt;
        }
        return $crypt;
    }

    /**
     * @param string $data
     *
     * @return bool
     */
    public function valideDecrypt(string $data, bool $reuqest = true): bool
    {
        if (!$this->auth->check('user')) {
            $this->updateSecurity();
        }
        if ($reuqest) {
            if ($this->auth->check('hash')) {
                $levelHash = $this->auth->getData('hash');
                if ($levelHash != $this->keyEncrypt['level']) {
                    $this->keyEncrypt['level'] = $levelHash['level'];
                }
            }
        }
        if (in_array(substr($data, 0, 1), [DS, DS_REVERSE]) !== false) {
            $data = substr($data, 1);
        }
        $levels = $this->validLevelAssetsToEncrypt($data, 3);
        if ($this->keyEncrypt['level'] != 0) {
            if (count($levels) > 0) {
                $this->assetsToEmcrypt($levels);
                if ($this->keyEncrypt['level'] == 3) {
                    if ($this->validBase64($this->hash)) {
                        $this->opensslKeys();
                        if ($this->valideOpenssl($this->hash)) {
                            if ($this->valideScrambledText($this->hash)) {
                                return true;
                            }
                        }
                    }
                    return false;
                }
                if ($this->keyEncrypt['level'] == 2) {
                    $this->opensslKeys();
                    if ($this->valideOpenssl($this->hash)) {
                        if ($this->valideScrambledText($this->hash)) {
                            return true;
                        }
                    }
                    return false;
                }
                if ($this->valideScrambledText($this->hash)) {
                    return true;
                }
                return false;
            }
            $this->assetsToEmcrypt();
            return false;
        }
        $this->assetsToEmcrypt();
        return false;
    }

    public function updateSecurity(string $status = 'desconnect'): Hash
    {
        $this->table->typeQuery = 'count';
        $options = [
            'fields' => ['count(securities.id) as count'],
            'conditions' => ['ip & ' => $this->http['request']->server['REMOTE_ADDR']]
        ];
        if ($this->table->dataQuery([$options], [['table' => 'securities']])->queryAssembly(
                ['deleteLimit' => [false]]
            )->excuteQuery(false, $options['fields'])->count > 0) {
            $options['fields'] = ['securities.id'];
            $this->table->typeQuery = 'first';
            $datas = [
                'fields' => ['status' => $status],
                'conditions' => [
                    'id & ' => $this->table->dataQuery([$options], [['table' => 'securities']])->queryAssembly(
                        ['deleteLimit' => [false]]
                    )->excuteQuery(false, $options['fields'])->id
                ]
            ];
            $this->table->typeQuery = 'update';
            $this->table->dataQuery([$datas], [['table' => 'securities']])->queryAssembly(['deleteLimit' => [false]]
            )->excuteQuery(false, $options['fields']);
            return $this;
        }
        $this->createSecurity(
            ['decrypting' => $optionsDefault['decrypting'], 'level' => $optionsDefault['level']],
            $this->http['request']->encryptKeys['internalwithexternalaccess'] === 'falso' && $this->http['request']->encryptKeys['status'] == 'desconnect'
        );
        return $this;
    }

    /**
     * @param string $hash
     * @param string $level
     *
     * @return array
     */
    public function validLevelAssetsToEncrypt(string $hash, string $level = '0'): array
    {
        if ($level == '0') {
            $level = $this->keyEncrypt['level'];
        }
        if (!empty($hash) && $hash != '/') {
            if (stripos($hash, '-') !== false) {
                list($hash, $levels) = explode('-', $hash);
                $this->hash = $level == 3 ? $hash . '==' : $hash;
                $this->hash = base64_encode(
                    preg_replace('@\x{FFFD}@u', '', base64_decode($this->hash))
                );
                $link = substr($levels, 2, 1) == 0 ? 'falso' : 'verdadeiro';
                if ($this->auth->check() || $link == 'verdadeiro') {
                    return [
                        'general' => substr($levels, 0, 1) == 0 ? 'falso' : 'verdadeiro',
                        'internal' => substr($levels, 1, 1) == 0 ? 'falso' : 'verdadeiro',
                        'internalwithexternalaccess' => $link
                    ];
                }
                return ['general' => 'falso', 'internal' => 'verdadeiro', 'internalwithexternalaccess' => 'falso'];
            }
            return [];
        }
        return [];
    }

    /**
     * @param string $data
     *
     * @return bool
     * @throws Exceptions
     */
    private function validBase64(string $data): bool
    {
        $result = true;
        if (preg_match('/^[a-zA-Z0-9\/\r\n+]*={0,2}$/', $data) === false) {
            return !$result;
        }
        $decrypt = base64_decode($data);
        if ($decrypt === false) {
            return !$result;
        }
        if (base64_encode($decrypt) !== $data) {
            return !$result;
        }
        $this->hash = $decrypt;
        return $result;
    }

    /**
     * @param string $data
     *
     * @return bool
     * @throws Exceptions
     */
    private function valideOpenssl(string $data): bool
    {
        $data = str_replace('_', DS, str_replace('|', '+', $data));
        $data = openssl_decrypt($data, 'AES-128-CBC', $this->keyEncrypt['key'], 0, $this->keyEncrypt['iv']);
        if ($data !== false) {
            $this->hash = $data;
            return true;
        }
        return false;
    }

    /**
     * @param string $data
     *
     * @return bool
     */
    private function valideScrambledText(string $data): bool
    {
        $path = '';
        for ($a = 1; $a < strlen($data); $a = $a + 2) {
            $path .= $data[$a];
        }
        if (count($this->auth->getSession('route')) > 0) {
            $this->hash = $path;
            return true;
        }
        return false;
    }

    public function alfanumero(): bool
    {
        return $this->alfanumerico;
    }

}
