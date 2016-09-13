<?php

namespace CommerceGuys\Guzzle\Oauth2\GrantType;

use CommerceGuys\Guzzle\Oauth2\AccessToken;


interface GrantTypeInterface
{
    /**
     * @param bool $forceCache
     *
     * @return AccessToken
     */
    public function getToken($forceCache = false);

    /**
     * @param string $name
     *
     * @return mixed|null
     */
    public function getConfigByName($name);

    /**
     * @return array
     */
    public function getConfig();

    /**
     * @param \Doctrine\Common\Cache\Cache $cache
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function setCache($cache);
}
