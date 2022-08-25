var passport = require('passport-strategy')
    , auth_hdr = require('./auth_header')
    , util = require('util')
    , url = require('url')
    , assign = require('./helpers/assign.js');



/**
 * Strategy constructor
 *
 * @param options
 *          secretOrKey: String or buffer containing the secret or PEM-encoded public key. Required unless secretOrKeyProvider is provided.
 *          secretOrKeyProvider: callback in the format secretOrKeyProvider(request, rawJwtToken, done)`,
 *                               which should call done with a secret or PEM-encoded public key
 *                               (asymmetric) for the given undecoded jwt token string and  request
 *                               combination. done has the signature function done(err, secret).
 *                               REQUIRED unless `secretOrKey` is provided.
 *          jwtFromRequest: (REQUIRED) Function that accepts a request as the only parameter and returns the either JWT as a string or null
 *          issuer: If defined issuer will be verified against this value
 *          audience: If defined audience will be verified against this value
 *          algorithms: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
 *          ignoreExpiration: if true do not validate the expiration of the token.
 *          passReqToCallback: If true the verify callback will be called with args (request, jwt_payload, done_callback).
 * @param verify - Verify callback with args (jwt_payload, done_callback) if passReqToCallback is false,
 *                 (request, jwt_payload, done_callback) if true.
 */
function JwtStrategy(options, verify) {

    passport.Strategy.call(this);
    this.name = 'jwt';

    this._secretOrKeyProvider = options.secretOrKeyProvider;

    if (options.secretOrKey) {
        if (this._secretOrKeyProvider) {
          	throw new TypeError('JwtStrategy has been given both a secretOrKey and a secretOrKeyProvider');
        }
        this._secretOrKeyProvider = function (request, rawJwtToken, done) {
            done(null, options.secretOrKey)
        };
    }

    if (!this._secretOrKeyProvider) {
        throw new TypeError('JwtStrategy requires a secret or key');
    }

    this._verify = verify;
    if (!this._verify) {
        throw new TypeError('JwtStrategy requires a verify callback');
    }

    this._jwtFromRequest = options.jwtFromRequest;
    if (!this._jwtFromRequest) {
        throw new TypeError('JwtStrategy requires a function to retrieve jwt from requests (see option jwtFromRequest)');
    }

    this._failWithChallenge = options.failWithChallenge;

    this._invalidTokenChallenge = options.invalidTokenChallenge || function (req, jwt_err) {
        return 'Bearer error="invalid_token" error_description="' + jwt_err.message + '"';
    }

    this._passReqToCallback = options.passReqToCallback;
    var jsonWebTokenOptions = options.jsonWebTokenOptions || {};
    //for backwards compatibility, still allowing you to pass
    //audience / issuer / algorithms / ignoreExpiration
    //on the options.
    this._verifOpts = assign({}, jsonWebTokenOptions, {
      audience: options.audience,
      issuer: options.issuer,
      algorithms: options.algorithms,
      ignoreExpiration: !!options.ignoreExpiration
    });

}
util.inherits(JwtStrategy, passport.Strategy);

function RequestValidationError (message, fileName, lineNumber) {
    var instance = new Error(message, fileName, lineNumber);
    Object.setPrototypeOf(instance, Object.getPrototypeOf(this));
    return instance;
}
RequestValidationError.prototype = Object.create(Error.prototype, {
  constructor: {
    value: Error,
    enumerable: false,
    writable: true,
    configurable: true
  }
});
/* istanbul ignore next */
if (Object.setPrototypeOf){
    Object.setPrototypeOf(RequestValidationError, Error);
} else {
    RequestValidationError.__proto__ = Error;
}
JwtStrategy.RequestValidationError = RequestValidationError;

/**
 * Allow for injection of JWT Verifier.
 *
 * This improves testability by allowing tests to cleanly isolate failures in the JWT Verification
 * process from failures in the passport related mechanics of authentication.
 *
 * Note that this should only be replaced in tests.
 */
JwtStrategy.JwtVerifier = require('./verify_jwt');



/**
 * Authenticate request based on JWT obtained from header or post body
 */
JwtStrategy.prototype.authenticate = function(req, options) {
    var token, challenge;
    var self = this;

    function legacyFail (info) {
        if (typeof info === 'string' || typeof info === 'number') {
            return self.fail(info);
        } else {
            // leave anything else out because passport would ignore it anyway
            return self.fail();
        }
    }

    try {
        token = self._jwtFromRequest(req);
    } catch (e) {
        if (self._failWithChallenge && e instanceof RequestValidationError) {
            challenge = e.message;
        } else {
            throw e;
        }
    }

    if (!token) {
        if (self._failWithChallenge) {
            if (!challenge) {
                challenge = 'Bearer error="invalid_request" error_description="The request is missing a ' +
                    'required parameter, includes an unsupported parameter or parameter value, repeats ' +
                    'the same parameter, uses more than one method for including an access token, or is ' +
                    'otherwise malformed."';
            }
            return self.fail(challenge, 400);
        } else {
            return legacyFail();
        }
    }

    this._secretOrKeyProvider(req, token, function(secretOrKeyError, secretOrKey) {
        if (secretOrKeyError) {
            legacyFail(secretOrKeyError);
        } else {
            // Verify the JWT
            JwtStrategy.JwtVerifier(token, secretOrKey, self._verifOpts, function(jwt_err, payload) {
                if (jwt_err) {
                    if (self._failWithChallenge) {
                        return self.fail(self._invalidTokenChallenge(req, jwt_err), 401);
                    } else {
                        return legacyFail();
                    }
                } else {
                    // Pass the parsed token to the user
                    var verified = function(err, user, info) {
                        if(err) {
                            return self.error(err);
                        } else if (!user) {
                            return legacyFail(info);
                        } else {
                            return self.success(user, info);
                        }
                    };

                    try {
                        if (self._passReqToCallback) {
                            self._verify(req, payload, verified);
                        } else {
                            self._verify(payload, verified);
                        }
                    } catch(ex) {
                        self.error(ex);
                    }
                }
            });
        }
    });
};



/**
 * Export the Jwt Strategy
 */
 module.exports = JwtStrategy;
