<?php

namespace IMedge\SshFeature;

use IMEdge\RpcApi\ApiMethod;
use IMEdge\RpcApi\ApiNamespace;
use Psr\Log\LoggerInterface;

use function React\Async\await as reactAwait;

#[ApiNamespace('ssh')]
class SshApi
{
    public function __construct(protected LoggerInterface $logger)
    {
    }

    /**
     * @param array $ips   Ip Address
     * @param array $types Types: dsa, ecdsa, ed25519, rsa, rsa1
     */
    #[ApiMethod]
    public function keyScan(array $ips, array $types): array
    {
        if (count($types) === 1 && str_contains($types[0], ',')) {
            $types = explode(',', $types[0]);
        }
        $scan = new SshKeyScan($ips, $types, $this->logger);

        return reactAwait($scan->start());
    }
}
