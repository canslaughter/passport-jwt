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


        function genHandlers(opts) {
            var user, info;
            var payload = { user: {}, info: {} };
            return {
                before: function(done) {
                    var strategy = new Strategy({
                            jwtFromRequest: function (r) { return test_data.valid_jwt.token; },
                            secretOrKey: 'secret',
                            challenges: opts.challenges,
                        },
                        function(jwt_payload, next) {
                            return next(null, payload.user, payload.info);
                        }
                    );

                    mockVerifier.reset();

                    chai.passport.use(strategy)
                        .success(function(u, i) {
                            user = u;
                            info = i;
                            done();
                        })
                        .authenticate();
                },
                itVerifies: function() {
                    sinon.assert.calledOnce(mockVerifier);
                    expect(mockVerifier.args[0][0]).to.equal(test_data.valid_jwt.token);
                },
                itForwards: function() {
                    expect(user).to.equal(payload.user);
                    expect(info).to.equal(payload.info);
                },
            }
        }

        describe('without challenges', function() {

            var handlers = genHandlers({});

            before(handlers.before);

            it("verifies the right jwt", handlers.itVerifies);

            it("forwards user and info", handlers.itForwards);

        });

        describe('with challenges', function() {

            describe('default invalidRequest challenge', function() {

                var handlers = genHandlers({ challenges: true });

                before(handlers.before);

                it("verifies the right jwt", handlers.itVerifies);

                it("forwards user and info", handlers.itForwards);

            });

            describe('custom invalidRequest challenge', function() {

                var handlers = genHandlers({
                    challenges: {
                        invalidRequest: function(r) {
                            return 'Bearer error="invalid_request"';
                        },
                    },
                });

                before(handlers.before);

                it("verifies the right jwt", handlers.itVerifies);

                it("forwards user and info", handlers.itForwards);

            });

        });

    });



    describe('handling request with NO JWT', function() {


        function genHandlers(opts) {
            var challenge, status;
            return {
                before: function(done) {
                    var strategy = new Strategy({
                            jwtFromRequest: function (r) {},
                            secretOrKey: 'secret',
                            challenges: opts.challenges,
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

        describe('without challenges', function() {

            var handlers = genHandlers({});

            before(handlers.before);

            it('should fail authentication', handlers.itFails.withUndefined);

            it('Should not try to verify anything', handlers.itDoesNotVerify);

        });

        describe('with challenges', function() {

            describe('default invalidRequest challenge', function() {

                var error_description = 'The request is missing a required parameter, includes an '
                    + 'unsupported parameter or parameter value, repeats the same '
                    + 'parameter, uses more than one method for including an access '
                    + 'token, or is otherwise malformed.';
                var handlers = genHandlers({
                    expectedChallenge: 'Bearer error="invalid_request" error_description="' + error_description + '"',
                    challenges: true,
                });

                before(handlers.before);

                it('should fail authentication', handlers.itFails.withChallenge);

                it('Should not try to verify anything', handlers.itDoesNotVerify);

            });

            describe('custom invalidRequest challenge', function() {

                var handlers = genHandlers({
                    expectedChallenge: 'custom challenge',
                    challenges: {
                        invalidRequest: function(r) {
                            return 'custom challenge';
                        },
                    },
                });

                before(handlers.before);

                it('should fail authentication', handlers.itFails.withChallenge);

                it('Should not try to verify anything', handlers.itDoesNotVerify);

            });

        });

    });


});
