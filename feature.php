<?php

/**
 * This is an IMEdge Node feature
 *
 * @var Feature $this
 */

use IMEdge\Node\Feature;
use IMedge\SshFeature\SshApi;

require __DIR__ . '/vendor/autoload.php';
$this->registerRpcApi(new SshApi($this->logger));
