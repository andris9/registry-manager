# RegistryAdmin

User manager for [Verdaccio](https://verdaccio.org/). Requires [regman plugin](https://github.com/andris9/verdaccio-regman) to be used for Verdaccio authentication.

[SREENSHOTS](https://cloudup.com/cL7FQ4fmzdP)

## Installation

```
$ npm install --production
```

## Running

```
$ node server.js
```

## User accounts

Default admin account credentials

-   Uusername: _admin_
-   Password: _admin_

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

-   Users with the `admin` tag can add and modify other users. Regular users can log in and edit their own settings only.
-   Users with the `publish` tag can are allowed to publish packages.
-   Users with the `bot` tag can not log in to the manager interface.

Package access uses Verdaccion configuration (so anonymous access is possible if allowed). Package publishing is only allowed to users with `admin` or `publish` tags. Verdaccio configuration about publishing is ignored.

## License

**ISC**
