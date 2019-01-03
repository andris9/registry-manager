# RegistryAdmin

User manager for private registry

## Installation

```
$ npm install --production
```

## Running

```
$ node server.js
```

## User accounts

User accounts are stored in a json file on disk. File location can be set in the config file. This file must be both readable and writable by the application process.

User account entry includes a password field. By default it can contain a plaintext password. Once application is started or reloaded, all plaintext passwords are converted to a pbkdf2-sha512 password hashes. If you forget your password, then just replace the password hash string in the json file with some plaintext password to log in.

```json
{
    "admin": {
        "enabled": true,
        "tags": ["admin"],
        "password": "admin"
    }
}
```

Users with the `admin` tag can add and modify other users.

Users with the `publish` tag can are allowed to publish packages.

## License

**ISC**
