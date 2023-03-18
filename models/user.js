/** User class for message.ly */
const { BCRYPT_WORK_FACTOR } = require('../config');
const bcrypt = require('bcrypt');
const db = require('../db');
const ExpressError = require('../expressError');

/** User of the site. */

class User {
    /** register new user -- returns
     *    {username, password, first_name, last_name, phone}
     */

    static async register({
        username,
        password,
        first_name,
        last_name,
        phone,
    }) {
        try {
            if (!username || !password || !first_name || !last_name || !phone) {
                throw new ExpressError(
                    'Missing data. All fields are required.',
                    400
                );
            }
            // hash password
            const hashedPassword = await bcrypt.hash(
                password,
                BCRYPT_WORK_FACTOR
            );

            const date = new Date();

            const noTimeZone = new Date(date.toISOString().slice(0, -1));

            // save to db
            const results = await db.query(
                `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING username, password, first_name, last_name, phone`,
                [
                    username,
                    hashedPassword,
                    first_name,
                    last_name,
                    phone,
                    noTimeZone,
                    noTimeZone,
                ]
            );
            return results.rows[0];
        } catch (e) {
            if (e.code === '23505') {
                throw new ExpressError(
                    'Username taken. Please pick another!',
                    400
                );
            } else {
                throw e;
            }
        }
    }

    /** Authenticate: is this username/password valid? Returns boolean. */

    static async authenticate(username, password) {
        if (!username || !password) {
            throw new ExpressError('Username and password required', 400);
        }
        const results = await db.query(
            `SELECT username, password 
            FROM users
            WHERE username = $1`,
            [username]
        );
        const user = results.rows[0];
        if (user) {
            if (await bcrypt.compare(password, user.password)) {
                return true;
            }
        } else {
            return false;
        }
    }

    /** Update last_login_at for user */

    static async updateLoginTimestamp(username) {
        const currentDate = new Date();
        const user = await db.query(
            `UPDATE users SET last_login_at=$1
          WHERE username = $2`,
            [currentDate, username]
        );
        return { message: 'Time updated successfully' };
    }

    /** All: basic info on all users:
     * [{username, first_name, last_name, phone}, ...] */

    static async all() {
        const results = await db.query(
            `SELECT username, first_name, last_name, phone 
        FROM users`
        );
        return results.rows;
    }

    /** Get: get user by username
     *
     * returns {username,
     *          first_name,
     *          last_name,
     *          phone,
     *          join_at,
     *          last_login_at } */

    static async get(username) {
        const results = await db.query(
            `SELECT username, 
        first_name, 
        last_name, 
        phone, 
        join_at, 
        last_login_at
        FROM users WHERE username = $1`,
            [username]
        );

        const user = results.rows[0];

        if (user === undefined) {
            throw new ExpressError(`User not found: ${username}`, 404);
        }
        return user;
    }

    /** Return messages from this user.
     *
     * [{id, to_user, body, sent_at, read_at}]
     *
     * where to_user is
     *   {username, first_name, last_name, phone}
     */

    static async messagesFrom(username) {
        const result = await db.query(
            `SELECT m.id,
                    m.from_username,
                    f.first_name AS from_first_name,
                    f.last_name AS from_last_name,
                    f.phone AS from_phone,
                    m.to_username,
                    t.first_name AS to_first_name,
                    t.last_name AS to_last_name,
                    t.phone AS to_phone,
                    m.body,
                    m.sent_at,
                    m.read_at
              FROM messages AS m
                JOIN users AS f ON m.from_username = f.username
                JOIN users AS t ON m.to_username = t.username
              WHERE m.from_username = $1`,
            [username]
        );

        let m = result.rows[0];

        if (!m) {
            throw new ExpressError(`No such message: ${id}`, 404);
        }

        return [
            {
                id: m.id,
                body: m.body,
                sent_at: m.sent_at,
                read_at: m.read_at,
                to_user: {
                    username: m.to_username,
                    first_name: m.to_first_name,
                    last_name: m.to_last_name,
                    phone: m.to_phone,
                },
            },
        ];
    }

    /** Return messages to this user.
     *
     * [{id, from_user, body, sent_at, read_at}]
     *
     * where from_user is
     *   {username, first_name, last_name, phone}
     */

    static async messagesTo(username) {
        const result = await db.query(
            `SELECT m.id,
                    m.from_username,
                    f.first_name AS from_first_name,
                    f.last_name AS from_last_name,
                    f.phone AS from_phone,
                    m.to_username,
                    t.first_name AS to_first_name,
                    t.last_name AS to_last_name,
                    t.phone AS to_phone,
                    m.body,
                    m.sent_at,
                    m.read_at
              FROM messages AS m
                JOIN users AS f ON m.from_username = f.username
                JOIN users AS t ON m.to_username = t.username
              WHERE m.to_username = $1`,
            [username]
        );

        let m = result.rows[0];

        if (!m) {
            throw new ExpressError(`No such message: ${id}`, 404);
        }

        return [
            {
                id: m.id,
                body: m.body,
                sent_at: m.sent_at,
                read_at: m.read_at,
                from_user: {
                    username: m.from_username,
                    first_name: m.from_first_name,
                    last_name: m.from_last_name,
                    phone: m.from_phone,
                },
            },
        ];
    }
}

module.exports = User;
