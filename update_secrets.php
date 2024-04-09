<?php

declare(strict_types=1);

if (!extension_loaded('sodium')) {
    echo "[-] The sodium extension is not loaded.\n";

    exit(1);
}

echo '------------------------'."\n";

try {
    $config = validateConfigFile(getenv('INPUT_CONFIG_PATH'));
    echo "[+] Configuration file loaded successfully\n";
} catch (Throwable $e) {
    echo "[-] Error while validating the configuration file. Error: {$e->getMessage()}\n";

    exit(1);
}

$detectedEnvironment = getenv('TARGET_ENVIRONMENT');
if (false === $detectedEnvironment) {
    echo "[-] No environment detected. Exiting.\n";

    exit(1);
}
echo "[+] Detected environment: {$detectedEnvironment}\n";

if (!isset($config['environments'][$detectedEnvironment])) {
    echo "[-] No configuration found for environment: {$detectedEnvironment}. Exiting.\n";

    exit(1);
}
echo "[+] Configuration found for the targeted environment\n";

$environmentConfig = $config['environments'][$detectedEnvironment];
if (!isset($environmentConfig['infisicalEnvName'])) {
    echo "[!] No custom infisical environment name found. Using the environment name as infisical environment name.\n";
    $environmentConfig['infisicalEnvName'] = $detectedEnvironment;
}

$foldersToCheck = array_map(
    fn (string $folder) => str_starts_with($folder, '/') ? $folder : "/{$folder}",
    array_unique(array_merge($config['commonFolders'], $environmentConfig['folders']))
);
if (0 === count($foldersToCheck)) {
    echo "[-] No folders to check for secrets on infisical: {$detectedEnvironment}. Exiting.\n";

    exit(1);
}
echo "[+] Folders to check for secrets on infisical: \n";
foreach ($foldersToCheck as $folder) {
    echo "    - {$folder}\n";
}

$existingSecretsNames = fetchGithubSecretsFromEnv($detectedEnvironment);
echo '[+] Total secrets found on github: '.count($existingSecretsNames)."\n";

echo "[+] Fetching public key infos\n";
$publicKeyInfos = fetchEnvironmentPublicKeyInfos($detectedEnvironment);
echo "[+] Public key infos fetched\n";

$computedSecrets = [];
$computedSecretsNames = [];
foreach ($foldersToCheck as $folder) {
    $output = [];
    $command = sprintf('infisical export --env=%s -f json --path="%s" 2>&1', $detectedEnvironment, $folder);
    $output = @shell_exec($command);

    try {
        $secrets = json_decode($output, true, flags: JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        echo "[-] Error while running command: {$command}\n";
        echo "{$output}\n";

        if ($config['strict']) {
            exit(1);
        }

        continue;
    }

    if (empty($secrets)) {
        echo "[-] No secrets found for folder: {$folder}\n";

        if ($config['strict']) {
            exit(1);
        }

        continue;
    }

    $computedSecrets = array_merge(
        $computedSecrets,
        array_map(function (array $secret) use (&$computedSecretsNames, &$environmentConfig, &$folder) {
            $computedSecretName = sprintf(
                '' === trim($environmentConfig['variableName']) ? '%s' : $environmentConfig['variableName'],
                computeSecretName($secret['key'], $folder)
            );
            $computedSecretsNames[] = $computedSecretName;

            return [
                'name' => $computedSecretName,
                'value' => $secret['value'],
            ];
        }, $secrets)
    );
}

$computedSecretsCount = count($computedSecrets);

echo "[+] Total secrets found on infisical: {$computedSecretsCount}\n";
echo "[+] Diffing secrets between github and computed infisical secrets\n";
$secretsToAdd = array_filter($computedSecrets, function (array $secret) use (&$existingSecretsNames) {
    return !in_array($secret['name'], $existingSecretsNames, true);
});
$secretsToAddCount = count($secretsToAdd);

$secretsNamesToRemove = array_filter($existingSecretsNames, function (string $secretName) use (&$computedSecretsNames) {
    return !in_array($secretName, $computedSecretsNames, true);
});
$secretsNamesToRemoveCount = count($secretsNamesToRemove);

echo "------------------------\n";
echo sprintf(
    "[+] Total secrets to add: %d (%s)\n",
    $secretsToAddCount,
    implode(', ', array_map(fn ($secret) => $secret['name'], $secretsToAdd))
);
echo sprintf(
    "[+] Total secrets to update: %d (%s)\n",
    $computedSecretsCount - $secretsToAddCount,
    implode(', ', $computedSecretsNames)
);

if ($config['clean']) {
    echo sprintf(
        "[+] Total secrets to remove: %d (%s)\n",
        $secretsNamesToRemoveCount,
        implode(', ', $secretsNamesToRemove)
    );
}
echo "------------------------\n";

$secretsUpdated = 0;
foreach ($computedSecrets as $secret) {
    try {
        setGithubSecret(
            name: $secret['name'],
            base64Secret: encryptGithubSecret($secret['value'], $publicKeyInfos['key']),
            publicKeyId: $publicKeyInfos['key_id'],
            env: $detectedEnvironment
        );
        ++$secretsUpdated;
    } catch (Throwable $e) {
        echo "[-] Error while setting secret {$secret['name']} on github. Error: {$e->getMessage()}\n";

        if ($config['strict']) {
            exit(1);
        }
    }
}

echo "[+] Total secrets updated: {$secretsUpdated}/{$computedSecretsCount}\n";

if ($config['clean']) {
    echo "[+] Cleaning {$secretsNamesToRemoveCount} secrets\n";
    foreach ($secretsNamesToRemove as $secretName) {
        try {
            removeGithubSecret($secretName, $detectedEnvironment);
        } catch (Throwable $e) {
            echo "[-] Error while removing secret {$secretName} on github. Error: {$e->getMessage()}\n";

            if ($config['strict']) {
                exit(1);
            }
        }
    }
}
echo "[+] Done\n";

function computeSecretName(string $baseName, string $folder): string
{
    $folder = ltrim($folder, '/');
    $baseName = str_replace([' ', '-'], '_', $baseName);
    $folder = str_replace([' ', '-', '/'], '_', $folder);

    if (empty($folder)) {
        return strtoupper($baseName);
    }

    return strtoupper($folder).'_'.strtoupper($baseName);
}

/**
 * @throws RuntimeException
 */
function getAppNameFromEnvVariable(): string
{
    $repository = getenv('GITHUB_REPOSITORY');
    if (false === $repository) {
        throw new RuntimeException('GITHUB_REPOSITORY env variable is not set.');
    }

    return explode('/', $repository)[1];
}

function getCurlHeaders(): array
{
    return [
        'Accept: application/vnd.github.v3+json',
        'Authorization: token '.getenv('REST_GITHUB_TOKEN'),
        'User-Agent: '.getAppNameFromEnvVariable(),
    ];
}

/**
 * @throws RuntimeException
 */
function fetchGithubSecretsFromEnv(string $env, int $page = 1): array
{
    $curl = curl_init();
    curl_setopt_array($curl, [
        CURLOPT_URL => sprintf(
            'https://api.github.com/repositories/%s/environments/%s/secrets?per_page=100&page=%d',
            getenv('GITHUB_REPOSITORY_ID'),
            $env,
            $page
        ),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => getCurlHeaders(),
    ]);

    $response = curl_exec($curl);
    $statusCode = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);

    if (false === $response) {
        throw new RuntimeException(sprintf(
            'Error while fetching secrets from github. Error: %s',
            curl_error($curl)
        ));
    }
    if (200 !== $statusCode) {
        throw new RuntimeException(sprintf(
            'Error while fetching secrets from github. Status code: %d Response: %s',
            $statusCode,
            $response
        ));
    }

    $response = json_decode($response, true, flags: JSON_THROW_ON_ERROR);
    $remainingSecretsCount = $response['total_count'] - ($page * 100);
    if ($remainingSecretsCount > 0) {
        $response = array_merge($response, fetchGithubSecretsFromEnv($env, $page + 1));
    }

    curl_close($curl);

    return array_map(fn ($secret) => $secret['name'], $response['secrets']);
}

/**
 * @throws RuntimeException
 */
function fetchEnvironmentPublicKeyInfos(string $env): array
{
    $curl = curl_init();
    curl_setopt_array($curl, [
        CURLOPT_URL => sprintf(
            'https://api.github.com/repositories/%s/environments/%s/secrets/public-key',
            getenv('GITHUB_REPOSITORY_ID'),
            $env
        ),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => getCurlHeaders(),
    ]);

    $response = curl_exec($curl);
    $statusCode = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);

    if (false === $response) {
        throw new RuntimeException(sprintf(
            'Error while fetching secrets public key from github. Error: %s',
            curl_error($curl)
        ));
    }
    if (200 !== $statusCode) {
        throw new RuntimeException(sprintf(
            'Error while fetching secrets public key  from github. Status code: %d Response: %s',
            $statusCode,
            $response
        ));
    }

    $response = json_decode($response, true, flags: JSON_THROW_ON_ERROR);

    curl_close($curl);

    return $response;
}

/**
 * @throws SodiumException
 */
function encryptGithubSecret(string $value, string $key): string
{
    $messageBytes = sodium_crypto_box_seal($value, base64_decode($key));

    return base64_encode($messageBytes);
}

/**
 * @throws RuntimeException
 */
function setGithubSecret(string $name, string $base64Secret, string $publicKeyId, string $env): void
{
    $curl = curl_init();
    curl_setopt_array($curl, [
        CURLOPT_URL => sprintf(
            'https://api.github.com/repositories/%s/environments/%s/secrets/%s',
            getenv('GITHUB_REPOSITORY_ID'),
            $env,
            strtoupper($name)
        ),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => 'PUT',
        CURLOPT_POSTFIELDS => json_encode([
            'encrypted_value' => $base64Secret,
            'key_id' => $publicKeyId,
        ]),
        CURLOPT_HTTPHEADER => getCurlHeaders(),
    ]);

    $response = curl_exec($curl);
    if (false === $response) {
        throw new RuntimeException(sprintf(
            'Error while setting secret %s on github. Error: %s',
            $name,
            curl_error($curl)
        ));
    }

    $statusCode = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    if (201 !== $statusCode && 204 !== $statusCode) {
        throw new RuntimeException(sprintf(
            'Error while setting secret %s on github. Status code: %d',
            $name,
            $statusCode
        ));
    }

    curl_close($curl);
}

/**
 * @throws RuntimeException
 */
function removeGithubSecret(string $name, string $env): void
{
    $curl = curl_init();
    curl_setopt_array($curl, [
        CURLOPT_URL => sprintf(
            'https://api.github.com/repositories/%s/environments/%s/secrets/%s',
            getenv('GITHUB_REPOSITORY_ID'),
            $env,
            strtoupper($name)
        ),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => 'DELETE',
        CURLOPT_HTTPHEADER => getCurlHeaders(),
    ]);

    $response = curl_exec($curl);
    if (false === $response) {
        throw new RuntimeException(sprintf(
            'Error while removing secret %s on github. Error: %s',
            $name,
            curl_error($curl)
        ));
    }

    $statusCode = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    if (204 !== $statusCode) {
        throw new RuntimeException(sprintf(
            'Error while removing secret %s on github. Status code: %d',
            $name,
            $statusCode
        ));
    }

    curl_close($curl);
}

function validateConfigFile(string $filePath): array
{
    if (!file_exists($filePath)) {
        throw new RuntimeException('The configuration file does not exist.');
    }

    $config = require $filePath;

    if (!is_array($config)) {
        throw new RuntimeException('The configuration file must return an array.');
    }

    if (!array_key_exists('commonFolders', $config) || !array_key_exists('environments', $config)) {
        throw new RuntimeException("The configuration file must contain 'commonFolders' and 'environments' keys.");
    }

    if (!is_array($config['commonFolders']) || !is_array($config['environments'])) {
        throw new RuntimeException("The 'commonFolders' and 'environments' keys must be arrays.");
    }

    foreach ($config['environments'] as $environmentConfig) {
        if (!is_array($environmentConfig)) {
            throw new RuntimeException('The environment configuration must be an array.');
        }

        if (!array_key_exists('infisicalEnvName', $environmentConfig)
            || !array_key_exists('variableName', $environmentConfig)
            || !array_key_exists('folders', $environmentConfig)) {
            throw new RuntimeException(
                "The environment configuration must contain 'infisicalEnvName', 'variableName' and 'folders' keys."
            );
        }

        if (!is_string($environmentConfig['infisicalEnvName'])
            || !is_string($environmentConfig['variableName'])
            || !is_array($environmentConfig['folders'])) {
            throw new RuntimeException(
                "The 'infisicalEnvName' and 'variableName' keys must be strings and the 'folders' key must be an array."
            );
        }
    }

    return $config;
}
