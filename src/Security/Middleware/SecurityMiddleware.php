<?php

namespace Restfull\Security\Middleware;

use Restfull\Http\Middleware\Middleware;
use Restfull\Http\Request;
use Restfull\Http\Response;
use Restfull\Security\Security;

/**
 *
 */
class SecurityMiddleware extends Middleware
{

    /**
     * @var Security
     */
    private $security;

    /**
     * @param Request $request
     * @param Response $response
     */
    public function __construct(Request $request, Response $response)
    {
        parent::__construct($request, $response);
        $this->security = $this->request->bootstrap('security');
        return $this;
    }

    /**
     * @param object $next
     *
     * @return object
     */
    public function __invoke(object $next): object
    {
        $csrf = $this->request->csrfPost();
        if (!empty($csrf)) {
            $this->request->requestMethod();
            if ($this->security->valideCsrf($csrf)) {
                $this->request->route = $this->security->csrfOldRoute();
                $this->request->requestMethodGet();
            }
        }
        return $next();
    }
}