<?php

namespace IMedge\SshFeature;

use Psr\Log\LoggerInterface;
use React\ChildProcess\Process;
use React\Promise\Deferred;
use React\Promise\PromiseInterface;

use function array_shift;
use function count;
use function explode;
use function implode;
use function React\Promise\reject;
use function React\Promise\Stream\buffer;

class SshKeyScan
{
    protected int $port = 22;
    protected array $results;
    protected string $strFingerPrint = '';

    public function __construct(
        protected readonly array $ips,
        protected readonly array $types,
        protected readonly LoggerInterface $logger,
    ) {
        foreach ($ips as $ip) {
            $this->results[$ip] = (object) [
                'signature' => null,
                'ip'        => $ip,
                'types'     => [],
            ];
        }

        foreach ($types as $type) {
            $this->results[$type] = [];
        }
    }

    public function start(): PromiseInterface
    {
        $pending = [];
        $deferred = new Deferred();

        foreach ($this->types as $type) {
            $pending[$type] = $this
                ->runSshKeyScan($type)
                ->always(function () use ($type, &$pending, &$deferred) {
                    unset($pending[$type]);
                    if (empty($pending)) {
                        $this->getFingerPrints()->always(function () use ($deferred) {
                            $deferred->resolve($this->results);
                        });
                    }
                });
        }

        return $deferred->promise();
    }

    protected function & getIp($ip, $type)
    {
        if (! isset($this->results[$ip]->$type)) {
            $this->results[$ip]->$type = (object) [];
        }
        return $this->results[$ip]->$type;
    }

    protected function getType($ip, $type)
    {
        if (! isset($this->results[$ip]->types[$type])) {
            $this->results[$ip]->types[$type] = (object) [
                // protocol: 1, 2
                'protocol'    => null,
                // typename: dsa, ecdsa, ed25519, rsa, rsa1
                'typename'    => null,
                // keytype: ecdsa-sha2-nistp256, ecdsa-sha2-nistp384,
                //          ecdsa-sha2-nistp521, ssh-ed25519, ssh-dss, ssh-rsa
                'keytype'     => null,
                'bits'        => null,
                'fingerprint' => null,
                // base64-encoded key, for rsa1 this is 'bits exponent modulus'
                'pubkey'      => null,
            ];
        }

        return $this->results[$ip]->types[$type];
    }

    protected function processResult(string $type, string $stdout, string $stderr): void
    {
        $this->logger->info('AHA');
        $this->results[$type][] = (object) [
            'stdout' => $stdout,
            'stderr' => $stderr,
        ];
        $this->logger->info('ERRR');
        foreach (self::split($stderr) as $line) {
            if ($line[0] === '#') {
                list($ip, $signature) = explode(' ', substr($line, 2), 2);
                $ip = preg_replace('/:' . $this->port . '$/', '', $ip);
                $this->getIp($ip, $type)->signature = $signature;
            }
        }

        $this->logger->info('OUTT');
        foreach (self::split($stdout) as $line) {
            if (\trim($line) === 'no hostkey alg') {
                $this->logger->info('No hostkey alg: ' . $line);
                continue;
            }

            if ($type === 'rsa1' && $info = $this->parseRsa1Line($line)) {
                $this->logger->info('RSA1: ' . $line);
                $this->strFingerPrint .= $line . "\n";
            } elseif ($info = $this->parseLine($line, $type)) {
                $this->logger->info('RSA2: ' . $line);
                $this->strFingerPrint .= $line . "\n";
            } else {
                $this->logger->info('SKIP: ' . $line);
                // Skip this line
                continue;
            }
            if ($info) {
                $info->keytype = $type;
            }
        }
        $this->logger->info('SOSO');
    }

    protected function getFingerPrints(): PromiseInterface
    {
        if ($this->strFingerPrint === '') {
            $this->results['error'] = 'Got no fingerprint';
            return reject('Got no fingerprint');
        } else {
            return $this
                ->run('ssh-keygen -lf -', $this->strFingerPrint)
                ->then(function ($resolved) {
                    list($exitCode, $stdout, $stderr) = $resolved;
                    if ($exitCode === 0) {
                        $this->processPubKeys($stdout);
                    }
                }, function () {
                    $this->results['nono'] = 'no';
                });
        }
    }

    protected function processPubKeys(string $output): void
    {
        foreach (SshKeyScan::splitLines($output) as $line) {
            $parts = explode(' ', $line);
            if (count($parts) === 4) {
                $ip = $parts[2];
                $type = strtolower(ltrim(rtrim($parts[3], ')'), '('));
                $info = $this->getType($ip, $type);
                $info->bits        = $parts[0];
                $info->fingerprint = $parts[1];
            } else {
                // log("ERROR: Invalid fingerprint '$line'\n");
            }
        }
    }

    protected function runSshKeyScan($type)
    {
        $command = \sprintf(
            'exec ssh-keyscan -p %d -t %s %s',
            $this->port,
            $type,
            implode(' ', $this->ips)
        );
        $this->logger->notice($command);

        return $this->run($command)->then(function ($result) use ($type, $command) {
            list($exitCode, $stdout, $stderr) = $result;
            if ($exitCode === 0) {
                try {
                    $this->processResult($type, $stdout, $stderr);
                } catch (\Throwable $e) {
                    $this->logger->error($e->getMessage() . ' (' . $e->getFile() . ':' . $e->getLine() . ')');
                }
            } else {
                // Might still have signature!
                $this->results[$type][] = (object) [
                    'stdout'  => $stdout,
                    'stderr'  => $stderr,
                    'command' => "Running $command failed with $exitCode: $stderr",
                ];
                // reject("Running $command failed with $exitCode: $stderr");
            }
        }, function (\Throwable $e) use ($type, $command) {
            $this->results[$type][] = (object) [
                'error'   => 'ERR2: ' . $e->getMessage(),
                'command' => $command,
            ];
        });
    }

    protected function parseLine($line, $type)
    {
        # Protocol 2, Syntax:
        # host-or-namelist keytype base64-encoded-key
        $parts = explode(' ', $line);
        if (count($parts) === 3) {
            $info = & $this->results[array_shift($parts)]->$type;
            $info->protocol = 2;
            list($info->typename, $info->pubkey) = $parts;

            $this->logger->info('INFO: ' . json_encode($line));

            return $info;
        } else {
            $this->logger->info('NO LINE: ' . $line);
            return false;
        }
    }

    protected function parseRsa1Line($line)
    {
        # Protocol 1, Syntax:
        # host-or-namelist bits exponent modulus
        $parts = explode(' ', $line);
        if (count($parts) === 4) {
            $info = $this->results[array_shift($parts)]['rsa1'];
            $info->protocol = 1;
            $info->typename = 'rsa1';
            $info->pubkey = implode(' ', $parts);

            return $info;
        } else {
            return false;
        }
    }

    protected function run($command, $stdin = null): PromiseInterface
    {
        $process = new Process($command);
        $process->start();

        $stdout = null;
        $stderr = null;
        $deferred = new Deferred();
        $resolveIfDone = function () use (&$stdout, &$stderr, &$exitCode, $deferred) {
            if ($stdout === null || $stderr === null || $exitCode === null) {
                return;
            }

            $deferred->resolve([$exitCode, $stdout, $stderr]);
        };

        buffer($process->stdout)->then(function ($data) use (&$stdout, $resolveIfDone) {
            $stdout = $data;
            $resolveIfDone();
        });
        buffer($process->stderr)->then(function ($data) use (&$stderr, $resolveIfDone) {
            $stderr = $data;
            $resolveIfDone();
        });
        $exitCode = null;

        if ($stdin !== null) {
            $process->stdin->write($stdin);
            $process->stdin->close();
        }

        $process->on('exit', function ($code, $term) use (&$exitCode, $resolveIfDone) {
            if ($term === null) {
                $exitCode = $code;
            } else {
                $exitCode = 127 + $term; // TODO: Check this.
            }
            $resolveIfDone();
        });

        return $deferred->promise();
    }

    protected static function splitLines(string $string): array
    {
        return preg_split('/\n/', $string, -1, PREG_SPLIT_NO_EMPTY);
    }

    protected static function split(string $line): array
    {
        return \preg_split('/\r?\n/', $line, -1, PREG_SPLIT_NO_EMPTY);
    }
}
