var Strategy = require('../lib/strategy')
    , chai = require('chai')
    , sinon = require('sinon')
    , test_data= require('./testdata');


describe('Strategy', function() {

    var mockVerifier = null;

    before(function() {
        // Replace the JWT Verfier with a stub to capture the value
        // extracted from the request
        mockVerifier = sinon.stub();
        mockVerifier.callsArgWith(3, null, test_data.valid_jwt.payload);
        Strategy.JwtVerifier = mockVerifier;
    });



    describe('handling request JWT present in request', function() {

        before(function(done) {
            var strategy = new Strategy({
                    jwtFromRequest: function (r) { return test_data.valid_jwt.token; },
                    secretOrKey: 'secret',
                },
                function(jwt_payload, next) {
                    return next(null, {}, {});
                }
            );

            mockVerifier.reset();

            chai.passport.use(strategy)
                .success(function(u, i) {
                    done();
                })
                .authenticate();
        });

        it("verifies the right jwt", function() {
            sinon.assert.calledOnce(mockVerifier);
            expect(mockVerifier.args[0][0]).to.equal(test_data.valid_jwt.token);
        });

    });



    describe('handling request with NO JWT', function() {


        function genHandlers(opts) {
            var challenge, status;
            return {
                before: function(done) {
                    var strategy = new Strategy({
                            jwtFromRequest: opts.jwtFromRequest,
                            secretOrKey: 'secret',
                            failWithChallenge: opts.failWithChallenge,
                        },
                        function(jwt_payload, next) {
                            // Return values aren't important in this case
                            return next(null, {}, {});
                        }
                    );

                    mockVerifier.reset();

                    chai.passport.use(strategy)
                        .fail(function(c, s) {
                            challenge = c;
                            status = s;
                            done();
                        })
                        .req(function(req) {
                            req.body = {}
                        })
                        .authenticate();
                },
                itFails: {
                    withUndefined: function() {
                        expect(challenge).to.be.undefined;
                        expect(status).to.be.undefined;
                    },
                    withChallenge: function() {
                        expect(challenge).to.equal(opts.expectedChallenge);
                        expect(status).to.equal(400);
                    },
                },
                itDoesNotVerify: function() {
                    sinon.assert.notCalled(mockVerifier);
                },
            }
        }

        describe('without challenge', function() {

            var handlers = genHandlers({
                jwtFromRequest: function (r) {},
            });

            before(handlers.before);

            it('should fail authentication with undefined', handlers.itFails.withUndefined);

            it('Should not try to verify anything', handlers.itDoesNotVerify);

        });

        describe('with challenge', function() {

            describe('default', function() {

                var handlers = genHandlers({
                    jwtFromRequest: function (r) {},
                    failWithChallenge: true,
                    expectedChallenge: 'Bearer error="invalid_request" error_description="The request is missing a ' +
                        'required parameter, includes an unsupported parameter or parameter value, repeats ' +
                        'the same parameter, uses more than one method for including an access token, or is ' +
                        'otherwise malformed."',
                });

                before(handlers.before);

                it('should fail authentication with challenge and status', handlers.itFails.withChallenge);

                it('Should not try to verify anything', handlers.itDoesNotVerify);

            });

            describe('custom', function() {

                var handlers = genHandlers({
                    jwtFromRequest: function (r) {
                        throw new Strategy.RequestValidationError('custom challenge');
                    },
                    failWithChallenge: true,
                    expectedChallenge: 'custom challenge',
                });

                before(handlers.before);

                it('should fail authentication with challenge and status', handlers.itFails.withChallenge);

                it('Should not try to verify anything', handlers.itDoesNotVerify);

            });

        });


        describe('failWithChallenge disabled', function() {


            function genHandlers(opts) {
                var error;
                return {
                    before: function() {
                        var strategy = new Strategy({
                                jwtFromRequest: function(r) {
                                    throw opts.error;
                                },
                                secretOrKey: 'secret',
                            },
                            function(jwt_payload, next) {
                                // Return values aren't important in this case
                                return next(null, {}, {});
                            }
                        );

                        mockVerifier.reset();

                        try {
                            chai.passport.use(strategy)
                                .req(function(req) {
                                    req.body = {}
                                })
                                .authenticate();
                        } catch (e) {
                            error = e;
                        }
                    },
                    itThrows: function() {
                        expect(error).to.equal(opts.error);
                    },
                    itDoesNotVerify: function() {
                        sinon.assert.notCalled(mockVerifier);
                    },
                }
            }

            describe('arbitrary error', function() {

                var handlers = genHandlers({error: new Error('arbitrary error')});

                before(handlers.before);

                it('should throw error', handlers.itThrows);

                it('Should not try to verify anything', handlers.itDoesNotVerify);

            });

            describe('RequestValidationError', function() {

                var handlers = genHandlers({
                    error: new Strategy.RequestValidationError('arbitrary error'),
                });

                before(handlers.before);

                it('should throw error', handlers.itThrows);

                it('Should not try to verify anything', handlers.itDoesNotVerify);

            });

        });

    });


});
