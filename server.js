/* eslint no-console: 0 */
'use strict';

const config = require('wild-config');
const crypto = require('crypto');
const express = require('express');
const webapp = express();
const Joi = require('joi');
const fs = require('fs');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const sessions = new Map();

const userStorage = {
    load() {
        let db;
        try {
            db = fs.readFileSync(config.users.db, 'utf-8');
        } catch (err) {
            let newErr = new Error('Failed to load database file (diagnostics code: ' + err.code + ')');
            newErr.code = err.code;
            console.error(newErr.message);
            console.error(err);
            throw newErr;
        }

        try {
            db = JSON.parse(db);
        } catch (err) {
            let newErr = new Error('Invalid database file, please fix manually');
            newErr.code = err.code;
            console.error(newErr.message);
            console.error(err);
            throw newErr;
        }

        this.db = db;

        let updated = false;

        for (let username of Object.keys(db)) {
            let userData = db[username];
            // overwrite
            if (userData.password.indexOf('$pbkdf$') < 0) {
                let salt = crypto.randomBytes(16);
                userData.password =
                    '$pbkdf$' + salt.toString('base64') + '$' + crypto.pbkdf2Sync(userData.password, salt, 100000, 64, 'sha512').toString('base64');
                db[username] = userData;
                console.log('Re-hashing password for %s', username);
                updated = true;
            }
        }

        if (updated) {
            this.save(db);
        }

        return db;
    },

    get(username) {
        if (!this.db) {
            this.load();
        }
        let userData = this.db[username];
        if (!userData) {
            return false;
        }
        userData.username = username;
        userData.tags = [].concat(userData.tags || []);
        return userData;
    },

    list() {
        if (!this.db) {
            this.load();
        }

        return Object.keys(this.db)
            .map(username => {
                let userData = this.db[username];
                userData.username = username;
                userData.tags = [].concat(userData.tags || []);
                return userData;
            })
            .sort((a, b) =>
                a.username
                    .toLowerCase()
                    .trim()
                    .localeCompare(b.username.toLowerCase().trim())
            );
    },

    authenticate(username, password) {
        if (!this.db) {
            this.load();
        }
        if (!this.db.hasOwnProperty(username)) {
            return false;
        }
        let userData = this.db[username];
        if (!userData.enabled || !userData.password) {
            return false;
        }

        let parts = userData.password.split('$');
        let salt = Buffer.from(parts[2], 'base64');
        let hash = parts[3];

        if (crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('base64') !== hash) {
            return false;
        }

        userData.username = username;
        return userData;
    },

    save(db) {
        try {
            fs.writeFileSync(config.users.db, JSON.stringify(db, false, 4));
        } catch (err) {
            console.error('Failed to save database file');
            console.error(err.message);
            throw new Error('Failed to save database file (diagnostics code: ' + err.code + ')');
        }
        this.db = db;
    },

    create(username, userData) {
        let db = this.load();
        if (userData.username) {
            delete userData.username;
        }

        let salt = crypto.randomBytes(16);
        userData.password = '$pbkdf$' + salt.toString('base64') + '$' + crypto.pbkdf2Sync(userData.password, salt, 100000, 64, 'sha512').toString('base64');

        db[username] = userData;

        this.save(db);
    },

    update(username, userData) {
        let db = this.load();
        if (userData.username) {
            delete userData.username;
        }

        if (userData.password && userData.password.indexOf('$pbkdf$') !== 0) {
            let salt = crypto.randomBytes(16);
            userData.password = '$pbkdf$' + salt.toString('base64') + '$' + crypto.pbkdf2Sync(userData.password, salt, 100000, 64, 'sha512').toString('base64');
        }

        db[username] = userData;

        this.save(db);
    },

    delete(username) {
        let db = this.load();
        delete db[username];
        this.save(db);
    }
};

config.on('reload', () => {
    try {
        userStorage.load();
        console.log('User database reloaded from disk');
    } catch (err) {
        console.error('Failed to reload user database from disk');
        console.error(err);
    }
});

webapp.use(cookieParser());

webapp.use(
    bodyParser.urlencoded({
        extended: true,
        limit: config.www.postsize
    })
);

webapp.use((req, res, next) => {
    // no caching!
    res.set({
        'cache-control': 'no-cache',
        pragma: 'no-cache'
    });
    res.locals.time = Date.now();
    res.locals.registry = config.registry;
    next();
});

webapp.set('views', __dirname + '/views');
webapp.set('view engine', 'hbs');
webapp.use(express.static(__dirname + '/public'));

webapp.use((req, res, next) => {
    if (!req.cookies[config.www.csrfCookie]) {
        let csrfToken = crypto
            .randomBytes(16)
            .toString('base64')
            .replace(/[=]/g, '');
        req.cookies[config.www.csrfCookie] = csrfToken;
        res.set({
            'set-cookie': encodeURIComponent(config.www.csrfCookie) + '=' + encodeURIComponent(csrfToken) + '; Path=/; HttpOnly'
        });
    }
    req.csrfToken = res.locals._csrf = req.cookies[config.www.csrfCookie];

    if (typeof req.cookies[config.www.cookieName] === 'string') {
        let clearCookie = true;
        if (sessions.has(req.cookies[config.www.cookieName])) {
            let session = sessions.get(req.cookies[config.www.cookieName]);
            let userData = userStorage.get(session.username);
            if (userData && userData.enabled) {
                userData.username = session.username;
                userData.tags = [].concat(userData.tags || []);
                req.user = res.locals.user = userData;
                clearCookie = false;
                req.session = session;
            }
        }
        if (clearCookie) {
            sessions.delete(req.cookies[config.www.cookieName]);
            res.set({
                'set-cookie': encodeURIComponent(config.www.cookieName) + '=deleted; Path=/;expires=Thu, 01 Jan 1970 00:00:00 GMT'
            });
        }
    }

    let menuItems = (res.locals.menuItems = [
        {
            key: 'home',
            title: 'Home',
            url: '/'
        }
    ]);

    if (!req.user) {
        menuItems.push({
            key: 'login',
            title: 'Log in',
            url: '/webauth-login'
        });
    } else {
        if (req.user.tags.includes('admin')) {
            menuItems.push({
                key: 'users',
                title: 'Users',
                url: '/webauth-users'
            });
        }
        menuItems.push({
            key: 'profile',
            title: 'Profile',
            url: '/webauth-users/profile'
        });
        menuItems.push({
            key: 'logout',
            title: 'Log out',
            url: '/webauth-logout'
        });
    }

    req.setActiveMenu = key => {
        menuItems.forEach(item => {
            item.active = item.key === key;
        });
    };

    next();
});

webapp.use((req, res, next) => {
    if (req.method === 'POST' && (!req.body._csrf || req.body._csrf !== req.csrfToken)) {
        req.showError = {
            message: 'Invalid CSRF token, please refresh page and try again',
            statusCode: 403
        };
    }
    next();
});

webapp.use((req, res, next) => {
    if (req.showError) {
        res.status(req.showError.statusCode || 500);
        res.render('errormessage', {
            code: req.showError.statusCode || 500,
            message: req.showError.message || req.showError
        });
        return;
    }

    req.flash = (level, title, message) => {
        if (!req.session) {
            return;
        }
        req.session[level] = {
            title,
            message
        };
    };

    if (req.session && req.method === 'GET') {
        res.locals.error = req.session.error;
        res.locals.success = req.session.success;
        req.session.error = {};
        req.session.success = {};
    }

    next();
});

webapp.get('/webauth-logout', (req, res) => {
    if (sessions.has(req.cookies[config.www.cookieName])) {
        sessions.delete(req.cookies[config.www.cookieName]);
        res.set({
            'set-cookie': encodeURIComponent(config.www.cookieName) + '=deleted; Path=/;expires=Thu, 01 Jan 1970 00:00:00 GMT'
        });
    }
    res.redirect('/');
});

webapp.use('/webauth-users/delete', (req, res, next) => {
    if (!req.user || !req.user.tags.includes('admin')) {
        req.flash('error', 'Invalid permissions.', 'You do not have permissions to access restricted content');
        return res.redirect('/');
    }

    req.setActiveMenu('users');
    next();
});

webapp.post('/webauth-users/delete', (req, res) => {
    const schema = Joi.object().keys({
        username: Joi.string()
            .trim()
            .max(256)
            .label('Username')
            .required()
    });

    const validation = Joi.validate(req.body, schema, {
        abortEarly: false,
        convert: true,
        stripUnknown: true
    });

    let sendError = error => {
        let userData = userStorage.get(validation.value.username);
        if (!userData) {
            res.status(404);
            res.render('notfound');
            return;
        }
        res.render('users-edit', {
            error,
            form: userData
        });
    };

    if (validation.error) {
        return sendError({
            title: 'Error',
            message: validation.error.message
        });
    }

    if (req.user.username === validation.value.username) {
        return sendError({
            title: 'Error',
            message: 'Can not delete self'
        });
    }

    userStorage.delete(validation.value.username);

    req.flash('success', 'Success!', validation.value.username + ' was deleted from user storage');
    res.redirect('/webauth-users');
});

webapp.use('/webauth-users/edit', (req, res, next) => {
    if (!req.user || !req.user.tags.includes('admin')) {
        req.flash('error', 'Invalid permissions.', 'You do not have permissions to access restricted content');
        return res.redirect('/');
    }

    req.setActiveMenu('users');
    next();
});

webapp.get('/webauth-users/edit', (req, res) => {
    const schema = Joi.object().keys({
        username: Joi.string()
            .trim()
            .max(256)
            .label('Username')
            .required()
    });

    const validation = Joi.validate(req.query, schema, {
        abortEarly: false,
        convert: true,
        stripUnknown: true
    });

    if (validation.error) {
        req.flash('error', 'Input fail.', 'Failed to validate input');
        return res.redirect('/webauth-users');
    }

    let userData = userStorage.get(validation.value.username);
    if (!userData) {
        res.status(404);
        res.render('notfound');
        return;
    }

    res.render('users-edit', {
        form: {
            username: userData.username,
            enabled: !!userData.enabled,
            tags: userData.tags.join(', ')
        }
    });
});

webapp.post('/webauth-users/edit', (req, res) => {
    const schema = Joi.object().keys({
        username: Joi.string()
            .trim()
            .max(256)
            .label('Username')
            .required(),
        tags: Joi.string()
            .empty('')
            .trim()
            .max(256)
            .label('Tags'),
        password: Joi.string()
            .empty('')
            .max(256)
            .label('Password'),
        password2: Joi.string()
            .empty('')
            .max(256)
            .label('Password repeat'),
        enabled: Joi.boolean()
            .truthy(['Y', 'true', 'yes', 'on', 1])
            .falsy(['N', 'false', 'no', 'off', 0, ''])
            .default(false)
    });

    const validation = Joi.validate(req.body, schema, {
        abortEarly: false,
        convert: true,
        stripUnknown: true
    });

    let sendError = error => {
        res.render('users-edit', {
            error,
            form: validation.value,
            errors: error.errors || {}
        });
    };

    if (validation.error) {
        let errors = {};

        validation.error.details.forEach(detail => {
            errors[detail.context.key] = detail.message;
        });

        return sendError({
            title: 'Error',
            message: 'Input validation failed',
            errors
        });
    }

    if (validation.value.password && validation.value.password !== validation.value.password2) {
        return sendError({
            title: 'Error',
            message: 'Input validation failed',
            errors: {
                password: 'Passwords do not match'
            }
        });
    }

    let existingData = userStorage.get(validation.value.username);
    if (!existingData) {
        res.status(404);
        res.render('notfound');
        return;
    }

    let tags = (validation.value.tags || '')
        .split(',')
        .map(tag => tag.trim())
        .filter(tag => tag)
        .sort();

    if (validation.value.username === req.user.username) {
        let errors = {};
        if (!validation.value.enabled) {
            errors.enabled = 'Can not disable self';
        }
        if (!existingData.tags.includes('bot') && tags.includes('bot')) {
            errors.tags = 'Can not add "bot" tag to self';
        }
        if (existingData.tags.includes('admin') && !tags.includes('admin')) {
            errors.tags = 'Can not remove "admin" tag from self';
        }
        if (Object.keys(errors).length) {
            return sendError({
                title: 'Error',
                message: 'Input validation failed',
                errors
            });
        }
    }

    let userData = {
        enabled: validation.value.enabled,
        tags
    };

    if (validation.value.password) {
        userData.password = validation.value.password;
    } else {
        userData.password = existingData.password;
    }

    try {
        userStorage.update(validation.value.username, userData);
        req.flash('success', 'Success!', validation.value.username + ' was updated');
    } catch (err) {
        req.flash('error', 'Error!', err.message);
        return res.redirect('/webauth-users/edit?username=' + encodeURIComponent(validation.value.username));
    }

    res.redirect('/webauth-users');
});

webapp.use('/webauth-users/new', (req, res, next) => {
    if (!req.user || !req.user.tags.includes('admin')) {
        req.flash('error', 'Invalid permissions.', 'You do not have permissions to access restricted content');
        return res.redirect('/');
    }

    req.setActiveMenu('users');
    next();
});

webapp.get('/webauth-users/new', (req, res) => {
    res.render('users-new', { form: { enabled: true } });
});

webapp.post('/webauth-users/new', (req, res) => {
    const schema = Joi.object().keys({
        username: Joi.string()
            .trim()
            .max(256)
            .label('Username')
            .required(),
        tags: Joi.string()
            .empty('')
            .trim()
            .max(256)
            .label('Tags'),
        password: Joi.string()
            .max(256)
            .label('Password')
            .required(),
        password2: Joi.string()
            .max(256)
            .label('Password repeat')
            .required(),
        enabled: Joi.boolean()
            .truthy(['Y', 'true', 'yes', 'on', 1])
            .falsy(['N', 'false', 'no', 'off', 0, ''])
            .default(false)
    });

    const validation = Joi.validate(req.body, schema, {
        abortEarly: false,
        convert: true,
        stripUnknown: true
    });

    let sendError = error => {
        res.render('users-new', {
            error,
            form: validation.value,
            errors: error.errors || {}
        });
    };

    if (validation.error) {
        let errors = {};

        validation.error.details.forEach(detail => {
            errors[detail.context.key] = detail.message;
        });

        return sendError({
            title: 'Error',
            message: 'Input validation failed',
            errors
        });
    }

    if (validation.value.password !== validation.value.password2) {
        return sendError({
            title: 'Error',
            message: 'Input validation failed',
            errors: {
                password: 'Passwords do not match'
            }
        });
    }

    if (userStorage.get(validation.value.username)) {
        return sendError({
            title: 'Error',
            message: 'Selected username is already in use',
            errors: {
                username: 'This username already exists'
            }
        });
    }

    let tags = (validation.value.tags || '')
        .split(',')
        .map(tag => tag.trim())
        .filter(tag => tag)
        .sort();

    let userData = {
        enabled: validation.value.enabled,
        tags,
        password: validation.value.password
    };

    try {
        userStorage.create(validation.value.username, userData);
        req.flash('success', 'Success!', validation.value.username + ' was created');
    } catch (err) {
        req.flash('error', 'Error!', err.message);
        return res.redirect('/webauth-users/new');
    }

    res.redirect('/webauth-users');
});

webapp.use('/webauth-users/profile', (req, res, next) => {
    if (!req.user || req.user.tags.includes('bot')) {
        return res.redirect('/');
    }

    req.setActiveMenu('profile');
    next();
});

webapp.get('/webauth-users/profile', (req, res) => {
    res.render('users-profile', {
        form: req.user
    });
});

webapp.post('/webauth-users/profile', (req, res) => {
    const schema = Joi.object().keys({
        username: Joi.string()
            .trim()
            .max(256)
            .label('Username')
            .allow([req.user.username])
            .required(),
        password: Joi.string()
            .empty('')
            .max(256)
            .label('Password'),
        password2: Joi.string()
            .empty('')
            .max(256)
            .label('Password repeat')
    });

    const validation = Joi.validate(req.body, schema, {
        abortEarly: false,
        convert: true,
        stripUnknown: true
    });

    let sendError = error => {
        res.render('users-profile', {
            error,
            form: validation.value,
            errors: error.errors || {}
        });
    };

    if (validation.error) {
        let errors = {};

        validation.error.details.forEach(detail => {
            errors[detail.context.key] = detail.message;
        });

        return sendError({
            title: 'Error',
            message: 'Input validation failed',
            errors
        });
    }

    if (validation.value.password && validation.value.password !== validation.value.password2) {
        return sendError({
            title: 'Error',
            message: 'Input validation failed',
            errors: {
                password: 'Passwords do not match'
            }
        });
    }

    let existingData = userStorage.get(validation.value.username);
    if (!existingData) {
        res.status(404);
        res.render('notfound');
        return;
    }

    if (validation.value.password) {
        existingData.password = validation.value.password;
    }

    try {
        userStorage.update(validation.value.username, existingData);
        req.flash('success', 'Success!', 'Profile settings were updated');
    } catch (err) {
        req.flash('error', 'Error!', err.message);
    }

    res.redirect('/webauth-users/profile');
});

webapp.use('/webauth-users', (req, res, next) => {
    if (!req.user || !req.user.tags.includes('admin')) {
        req.flash('error', 'Invalid permissions.', 'You do not have permissions to access restricted content');
        return res.redirect('/');
    }

    req.setActiveMenu('users');
    next();
});

webapp.get('/webauth-users', (req, res) => {
    let users = userStorage.list().map((userData, i) => {
        userData.index = i + 1;
        return userData;
    });

    res.render('users', {
        users
    });
});

webapp.use('/webauth-login', (req, res, next) => {
    req.setActiveMenu('login');
    next();
});

webapp.get('/webauth-login', (req, res) => {
    res.render('login');
});

webapp.post('/webauth-login', (req, res) => {
    const schema = Joi.object().keys({
        username: Joi.string()
            .trim()
            .max(256)
            .label('Username')
            .required(),
        password: Joi.string()
            .max(256)
            .label('Password')
            .required()
    });

    const validation = Joi.validate(req.body, schema, {
        abortEarly: false,
        convert: true,
        stripUnknown: true
    });

    let sendError = error =>
        res.render('login', {
            error,
            form: validation.value
        });

    if (validation.error) {
        return sendError({
            title: 'Authentication failed!',
            message: validation.error.message
        });
    }

    let username = validation.value.username;
    let password = validation.value.password;

    let userData = userStorage.authenticate(username, password);

    if (!userData) {
        return sendError({
            title: 'Authentication failed!',
            message: 'Unknown or disabled user'
        });
    }

    if (userData.tags.includes('bot')) {
        return sendError({
            title: 'Authentication failed!',
            message: 'System accounts can not login here'
        });
    }

    let session = {
        id: crypto.randomBytes(20).toString('hex'),
        username,
        error: {},
        success: {}
    };

    sessions.set(session.id, session);

    res.set({
        'set-cookie': encodeURIComponent(config.www.cookieName) + '=' + encodeURIComponent(session.id) + '; Path=/; HttpOnly'
    });

    res.redirect('/');
});

webapp.get('/', (req, res) => {
    req.setActiveMenu('home');
    res.render('index', {
        backends: [].concat(config.backends || []).map((backend, i) => {
            backend = JSON.parse(JSON.stringify(backend));
            backend.index = i + 1;
            return backend;
        })
    });
});

webapp.use('/', (req, res) => {
    if (req.notFound) {
        res.status(404);
        res.render('notfound');
        return;
    }

    res.status(403);
    res.render('error');
});

process.title = 'registry-manager';

// Try to load user database. Might throw
userStorage.load();

webapp.listen(config.www.port, () => {
    console.log('Server listening on port %s', config.www.port);
});
