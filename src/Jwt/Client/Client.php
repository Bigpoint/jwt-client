<?php
namespace Jwt\Client;

use \Doctrine\Common\Cache;
use \Http;
use \Monolog;

class Client
{
    /**
     * @var string
     */
    private $providerUrl = '';

    /**
     * @var Http\Caller
     */
    private $httpCaller = null;

    /**
     * @var Cache\Cache
     */
    private $cache = null;

    /**
     * Cache duration in seconds. Only used if cache duration can't be determined from token.
     *
     * @var int
     */
    private $cacheDurationFallback = 3600;

    /**
     * @var Monolog\Logger
     */
    private $logger = null;

    /**
     * @param string         $providerUrl
     * @param Http\Caller    $httpCaller
     * @param Cache\Cache    $cache
     * @param int            $cacheDurationFallback Cache duration in seconds (default 3600). Only used if cache
     *                                              duration can't be determined from token.
     * @param Monolog\Logger $logger
     */
    public function __construct(
        $providerUrl,
        Http\Caller $httpCaller,
        Cache\Cache $cache,
        $cacheDurationFallback,
        Monolog\Logger $logger
    ) {
        $this->providerUrl           = $providerUrl;
        $this->httpCaller            = $httpCaller;
        $this->cache                 = $cache;
        $this->cacheDurationFallback = $cacheDurationFallback;
        $this->logger                = $logger;
    }

    /**
     * Gets a token from the JWT provider and stores it in a local cache.
     *
     * @note At the moment there is no verification and validation of the token.
     *
     * @param string $username
     * @param string $password
     *
     * @return string
     *
     * @throws Exception if we can't get a token
     */
    public function getToken($username, $password)
    {
        if (true === $this->cache->contains($username)) {
            $this->logger->addInfo(\sprintf('using cache for %s', $username));

            return $this->cache->fetch($username);
        }

        $token = $this->getTokenFromProvider($username, $password);

        // read cacheDurationFallback from token
        $now              = new \DateTime('now', new \DateTimeZone('UTC'));
        $nowTimestamp     = $now->getTimestamp();
        $expipreTimestamp = $this->getExpireTimestamp($token);

        $cacheDuration = $expipreTimestamp - $nowTimestamp;

        if (0 >= $cacheDuration) {
            $cacheDuration = $this->cacheDurationFallback;
        }

        $this->cache->save($username, $token, $cacheDuration);

        return $token;
    }

    /**
     * @param string $username
     * @param string $password
     *
     * @return string
     *
     * @throws Exception
     */
    private function getTokenFromProvider($username, $password)
    {
        $this->logger->addInfo(\sprintf('getting token from %s for %s', $this->providerUrl, $username));

        $result = $this->httpCaller->post(
            \sprintf('%s/user_token', \rtrim($this->providerUrl, '/')),
            \json_encode(
                array(
                    'auth' => array(
                        'name'     => $username,
                        'password' => $password,
                    )
                )
            ),
            array(
                'Content-Type: application/json',
            )
        );

        if (201 !== $result['responseCode']) {
            $message = \sprintf('error calling jwt provider %s', \var_export($result, true));

            $this->logger->addError($message);

            throw new Exception($message);
        }

        $data = \json_decode($result['body'], true);

        if (false === \is_array($data)
            || false === \array_key_exists('jwt', $data)
            || true === empty($data['jwt'])
        ) {
            $message = \sprintf('error parsing jwt provider result %s', \var_export($result, true));

            $this->logger->addError($message);

            throw new Exception($message);
        }

        return $data['jwt'];
    }

    /**
     * @param string $token
     *
     * @return int
     */
    private function getExpireTimestamp($token)
    {
        $tokendata = \explode('.', $token);

        // invalid token
        if (false === \is_array($tokendata) || 2 > \count($tokendata)) {
            return 0;
        }

        $payload = \json_decode(\base64_decode($tokendata[1]), true);

        // invalid payload
        if (false === \is_array($payload) || false === \array_key_exists('exp', $payload)) {
            return 0;
        }

        return $payload['exp'];
    }
}
