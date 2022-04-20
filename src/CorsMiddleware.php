<?php

declare(strict_types=1);

namespace Whirlwind\Middleware\Cors;

use Neomerx\Cors\Contracts\AnalysisResultInterface;
use Neomerx\Cors\Contracts\AnalyzerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

class CorsMiddleware implements MiddlewareInterface
{
    protected $analyzer;

    protected $responseFactory;

    public function __construct(AnalyzerInterface $analyzer, ResponseFactoryInterface $responseFactory)
    {
        $this->analyzer = $analyzer;
        $this->responseFactory = $responseFactory;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $cors = $this->analyzer->analyze($request);
        $type = $cors->getRequestType();
        if (\in_array($type, [
            AnalysisResultInterface::ERR_NO_HOST_HEADER,
            AnalysisResultInterface::ERR_ORIGIN_NOT_ALLOWED,
            AnalysisResultInterface::ERR_METHOD_NOT_SUPPORTED,
            AnalysisResultInterface::ERR_HEADERS_NOT_SUPPORTED
        ])) {
            return $this->responseFactory->createResponse(403);
        }
        if ($type == AnalysisResultInterface::TYPE_REQUEST_OUT_OF_CORS_SCOPE) {
            return $handler->handle($request);
        }
        if ($type == AnalysisResultInterface::TYPE_PRE_FLIGHT_REQUEST) {
            $response = $this->responseFactory->createResponse(200);
            return $this->withCorsHeaders($response, $cors);
        }
        $response = $handler->handle($request);
        return $this->withCorsHeaders($response, $cors);
    }

    protected function withCorsHeaders(
        ResponseInterface $response,
        AnalysisResultInterface $cors
    ): ResponseInterface {
        foreach ($cors->getResponseHeaders() as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        return $response;
    }
}
