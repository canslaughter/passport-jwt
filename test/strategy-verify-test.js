var chai = require('chai')
    , Strategy = require('../lib/strategy')
    , test_data = require('./testdata')
    , sinon = require('sinon')
    , verify = require('../lib/verify_jwt')
    , extract_jwt = require('../lib/extract_jwt');


describe('Strategy', function() {

    before(function() {
        Strategy.JwtVerifier = sinon.stub();
        Strategy.JwtVerifier.callsArgWith(3, null, test_data.valid_jwt.payload);
    });

    describe('Handling a request with a valid JWT and succesful verification', function() {

        var user, info;

        before(function(done) {
            var strategy = new Strategy({
                jwtFromRequest: extract_jwt.fromAuthHeaderAsBearerToken(),
                secretOrKey: 'secret',
            }, function(jwt_payload, next) {
                return next(null, {user_id: 1234567890}, {foo:'bar'});
            });

            chai.passport.use(strategy)
                .success(function(u, i) {
                    user = u;
                    info = i;
                    done();
                })
                .req(function(req) {
                    req.headers['authorization'] = "bearer " + test_data.valid_jwt.token;
                })
                .authenticate();
        });


        it('should provide a user', function() {
            expect(user).to.be.an.object;
            expect(user.user_id).to.equal(1234567890);
        });


        it('should forward info', function() {
            expect(info).to.be.an.object;
            expect(info.foo).to.equal('bar');
        });

    });



    describe('handling a request with valid jwt and failed verification', function() {

        function genHandlers(opts) {
            var challenge, status;
            return {
                before: function(done) {
                    var strategy = new Strategy({
                        jwtFromRequest: extract_jwt.fromAuthHeaderAsBearerToken(),
                        secretOrKey: 'secret'
                    }, function(jwt_payload, next) {
                        return next(null, false, opts.info);
                    });

                    chai.passport.use(strategy)
                        .fail(function(c, s) {
                            challenge = c;
                            status = s;
                            done();
                        })
                        .req(function(req) { 
                            req.headers['authorization'] = "bearer " + test_data.valid_jwt.token;
                        })
                        .authenticate();
                },
                itFails: {
                    withUndefined: function() {
                        expect(challenge).to.be.undefined;
                        expect(status).to.be.undefined;
                    },
                    withChallenge: function() {
                        expect(challenge).to.equal(opts.info);
                        expect(status).to.be.undefined;
                    },
                },
            };
        }

        describe('info is an object', function() {

            var handlers = genHandlers({info: {message: 'invalid user'}});

            before(handlers.before);

            it('should fail without challenge or status', handlers.itFails.withUndefined);

        });

        describe('info is a string', function() {

            var handlers = genHandlers({info: 'some challenge'});

            before(handlers.before);

            it('should fail with challenge', handlers.itFails.withChallenge);

        });

        describe('info is a number', function() {

            var handlers = genHandlers({info: 401});

            before(handlers.before);

            it('should fail with challenge', handlers.itFails.withChallenge);

        });

    });



    describe('handling a request with a valid jwt and an error during verification', function() {

        function genHandlers(opts) {
            var err;
            return {
                before: function(done) {
                    var strategy = new Strategy({
                        jwtFromRequest: extract_jwt.fromAuthHeaderAsBearerToken(),
                        secretOrKey: 'secret'
                    }, opts.verify);

                    chai.passport.use(strategy)
                        .error(function(e) {
                            err = e;
                            done();
                        })
                        .req(function(req) { 
                            req.headers['authorization'] = "bearer " + test_data.valid_jwt.token;
                        })
                        .authenticate();
                },
                itErrors: function() {
                    expect(err).to.be.an.instanceof(Error);
                    expect(err.message).to.equal('ERROR');
                },
            };
        }

        var handlers = genHandlers({
            verify: function(jwt_payload, next) {
                return next(new Error("ERROR"));
            },
        });

        before(handlers.before);

        it('should error', handlers.itErrors);

    });



    describe('handling a request with a valid jwt and an exception during verification', function() {

        var err;

        before(function(done) {
            var strategy = new Strategy({
                jwtFromRequest: extract_jwt.fromAuthHeaderAsBearerToken(),
                secretOrKey: 'secret',
            }, function(jwt_payload, next) {
                throw new Error("EXCEPTION");
            });

            chai.passport.use(strategy)
                .error(function(e) {
                    err = e;
                    done();
                })
                .req(function(req) { 
                    req.headers['authorization'] = "bearer " + test_data.valid_jwt.token;
                })
                .authenticate();
        });

        it('should error', function() {
            expect(err).to.be.an.instanceof(Error);
            expect(err.message).to.equal('EXCEPTION');
        });

    });



    describe('handling a request with a valid jwt and option passReqToCallback is true', function() {

        function genHandlers(opts) {
            var expectedRequest;
            return {
                before: function(done) {
                    var strategy = new Strategy({
                        passReqToCallback: true,
                        jwtFromRequest: extract_jwt.fromAuthHeaderAsBearerToken(),
                        secretOrKey: 'secret',
                    }, opts.verify);

                    chai.passport.use(strategy)
                        .success(function(u, i) {
                            done();
                        })
                        .req(function(req) {
                            req.headers['authorization'] = "bearer " + test_data.valid_jwt.token;
                            expectedRequest = req;
                        })
                        .authenticate();
                },
                itVerifies: function() {
                    expect(opts.capturedRequest()).to.equal(expectedRequest);
                },
            };
        }

        var req;
        var handlers = genHandlers({
            capturedRequest: function() {
                return req;
            },
            verify: function(request, jwt_payload, next) {
                // Capture the value passed in as the request argument
                req = request;
                return next(null, {user_id: 1234567890}, {foo:'bar'});
            },
        })

        before(handlers.before);

        it('will call verify with request as the first argument', handlers.itVerifies);

    });


    describe('handling a request when constructed with a secretOrKeyProvider function that succeeds', function() {

        function genHandlers(opts) {
            var fakeSecretOrKeyProvider, expectedRequest;
            return {
                before: function(done) {
                    fakeSecretOrKeyProvider = sinon.spy(opts.secretOrKeyProvider);
                    var strategy = new Strategy({
                        secretOrKeyProvider: fakeSecretOrKeyProvider,
                        jwtFromRequest: function(request) {
                            return 'an undecoded jwt string';
                        }
                    }, opts.verify);

                    chai.passport.use(strategy)
                        .success(function(u, i) {
                            done();
                        })
                        .req(function(req) {
                            expectedRequest = req;
                        })
                        .authenticate();
                },
                itReceivesReq: function() {
                    expect(fakeSecretOrKeyProvider.calledWith(
                        expectedRequest,
                        sinon.match.any,
                        sinon.match.any
                    )).to.be.true;
                },
                itReceivesJwt: function() {
                    expect(fakeSecretOrKeyProvider.calledWith(
                        sinon.match.any,
                        'an undecoded jwt string',
                        sinon.match.any
                    )).to.be.true;
                },
                itCallsVerifier: function() {
                    expect(Strategy.JwtVerifier.calledWith(
                            sinon.match.any,
                            'secret from callback',
                            sinon.match.any,
                            sinon.match.any
                    )).to.be.true;
                },
            };
        }

        var handlers = genHandlers({
            verify: function(jwtPayload, next) {
                return next(null, {user_id: 'dont care'}, {});
            },
            secretOrKeyProvider: function(request, token, done) {
                done(null, 'secret from callback');
            },
        });

        before(handlers.before);

        it('should call the fake secret or key provider with the request', handlers.itReceivesReq);

        it('should call the secretOrKeyProvider with the undecoded jwt', handlers.itReceivesJwt);

        it('should call JwtVerifier with the value returned from secretOrKeyProvider', handlers.itCallsVerifier);

    });


    describe('handling a request when constructed with a secretOrKeyProvider function that errors', function() {

        function genHandlers(opts) {
            var challenge, status;
            return {
                before: function(done) {
                    var strategy = new Strategy({
                        secretOrKeyProvider: opts.secretOrKeyProvider,
                        jwtFromRequest: function(request) {
                            return 'an undecoded jwt string';
                        }
                    }, function(jwtPayload, next) {
                        return next(null, {user_id: 'dont care'}, {});
                    });

                    chai.passport.use(strategy)
                        .fail(function(c, s) {
                            challenge = c;
                            status = s;
                            done();
                        })
                        .authenticate();
                },
                itFails: {
                    withUndefined: function() {
                        expect(challenge).to.be.undefined;
                        expect(status).to.be.undefined;
                    },
                    withChallenge: function() {
                        expect(challenge).to.equal(opts.secretOrKeyError);
                        expect(status).to.be.undefined;
                    },
                },
            };
        }

        describe('secretOrKeyError is an object', function() {

            var e = {message: 'invalid user'};
            var handlers = genHandlers({
                secretOrKeyError: e,
                secretOrKeyProvider: function(req, token, done) {
                    done(e);
                },
            });

            before(handlers.before);

            it('should fail without challenge or status', handlers.itFails.withUndefined);

        });

        describe('secretOrKeyError is a string', function() {

            var handlers = genHandlers({
                secretOrKeyError: 'some challenge',
                secretOrKeyProvider: function(req, token, done) {
                    done('some challenge');
                },
            });

            before(handlers.before);

            it('should fail with challenge', handlers.itFails.withChallenge);

        });

        describe('secretOrKeyError is a number', function() {

            var handlers = genHandlers({
                secretOrKeyError: 401,
                secretOrKeyProvider: function(req, token, done) {
                    done(401);
                },
            });

            before(handlers.before);

            it('should fail with challenge', handlers.itFails.withChallenge);

        });

    });
});
