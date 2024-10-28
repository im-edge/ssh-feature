<?php

/**
 * This is an IMEdge Node feature
 *
 * @var Feature $this
 */

use IMEdge\Node\Feature;
use IMedge\SshFeature\SshApi;

$this->registerRpcApi(new SshApi($this->logger));
