<?php

return [
    'commonFolders' => [
        '/', // root
    ],
    'environments' => [
        'staging' => [
            'infisicalEnvName' => 'staging',
            'variableName' => '%s', // the format of the variable name, %s will be replaced with current variable
            'folders' => [
                '/',
                'emtpy',
                'frontend',
            ],
        ],
    ],
    'strict' => false,
    'clean' => true,
];
