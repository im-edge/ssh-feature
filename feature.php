<?php

/**
 * This is an IMEdge Node feature
 *
 * @var Feature $this
 */

use IMEdge\Node\Feature;
use IMedge\SshFeature\SshApi;

throw new RuntimeException('SSH feature is not working right now');
$this->registerRpcApi(new SshApi($this->logger));
