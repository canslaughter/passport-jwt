var Strategy = require('../lib/strategy')
    , chai = require('chai')
    , test_data = require('./testdata')
    , sinon = require('sinon')
    , extract_jwt = require('../lib/extract_jwt');

describe('Strategy', function() {

    describe('calling JWT validation function', function() {

        before(function(done) {
            var verifyStub = sinon.stub();
            verifyStub.callsArgWith(1, null, {}, {});
            var options = {};
            options.issuer = "TestIssuer";
            options.audience = "TestAudience";
            options.secretOrKey = 'secret';
            options.algorithms = ["HS256", "HS384"];
            options.ignoreExpiration = false;
            options.jsonWebTokenOptions = {
              clockTolerance: 10,
              maxAge: "1h",
            };
            options.jwtFromRequest = extract_jwt.fromAuthHeaderAsBearerToken();
            var strategy = new Strategy(options, verifyStub);

            Strategy.JwtVerifier = sinon.stub();
            Strategy.JwtVerifier.callsArgWith(3, null, test_data.valid_jwt.payload);

            chai.passport.use(strategy)
                .success(function(u, i) {
                    done();
                })
                .req(function(req) {
                    req.headers['authorization'] = "bearer " + test_data.valid_jwt.token;
                })
                .authenticate();
        });


        it('should call with the right secret as an argument', function() {
            expect(Strategy.JwtVerifier.args[0][1]).to.equal('secret');
        });


        it('should call with the right issuer option', function() {
            expect(Strategy.JwtVerifier.args[0][2]).to.be.an.object;
            expect(Strategy.JwtVerifier.args[0][2].issuer).to.equal('TestIssuer');
        });


        it('should call with the right audience option', function() {
            expect(Strategy.JwtVerifier.args[0][2]).to.be.an.object;
            expect(Strategy.JwtVerifier.args[0][2].audience).to.equal('TestAudience');
        });

        it('should call with the right algorithms option', function() {
            expect(Strategy.JwtVerifier.args[0][2]).to.be.an.object;
            expect(Strategy.JwtVerifier.args[0][2].algorithms).to.eql(["HS256", "HS384"]);
        });

        it('should call with the right ignoreExpiration option', function() {
            expect(Strategy.JwtVerifier.args[0][2]).to.be.an.object;
            expect(Strategy.JwtVerifier.args[0][2].ignoreExpiration).to.be.false;
        });

        it('should call with the right maxAge option', function() {
            expect(Strategy.JwtVerifier.args[0][2]).to.be.an.object;
            expect(Strategy.JwtVerifier.args[0][2].maxAge).to.equal('1h');
        });

        it('should call with the right clockTolerance option', function() {
            expect(Strategy.JwtVerifier.args[0][2]).to.be.an.object;
            expect(Strategy.JwtVerifier.args[0][2].clockTolerance).to.equal(10);
        });

    });


    describe('handling valid jwt', function() {
        var payload;

        before(function(done) {
            var strategy = new Strategy({
                jwtFromRequest: extract_jwt.fromAuthHeaderAsBearerToken(),
                secretOrKey: 'secret'
            }, function(jwt_payload, next) {
                payload = jwt_payload;
                next(null, {}, {});
            });

            // Mock successful verification
            Strategy.JwtVerifier = sinon.stub();
            Strategy.JwtVerifier.callsArgWith(3, null, test_data.valid_jwt.payload);

            chai.passport.use(strategy)
                .success(function(u, i) {
                    done();
                })
                .req(function(req) {
                    req.headers['authorization'] = "bearer " + test_data.valid_jwt.token;
                })
                .authenticate();
        });


        it('should call verify with the correct payload', function() {
            expect(payload).to.deep.equal(test_data.valid_jwt.payload);
        });


    });


    describe('handling failing jwt', function() {

        function genHandlers(opts) {

            var challenge, status;
            var verify_spy = sinon.spy();

            return {
                before: function(done) {

                    verify_spy.reset();
                    var strategy = new Strategy({
                        jwtFromRequest: extract_jwt.fromAuthHeaderAsBearerToken(),
                        secretOrKey: 'secret',
                        challenges: opts.challenges,
                    }, verify_spy);

                    // Mock errored verification
                    Strategy.JwtVerifier = sinon.stub();
                    Strategy.JwtVerifier.callsArgWith(3, new Error("jwt expired"), false);

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
                itDoesNotVerify: function() {
                    sinon.assert.notCalled(verify_spy);
                },
                itFails: {
                    withChallenge: function() {
                        expect(challenge).to.equal(opts.expectedChallenge);
                        expect(status).to.equal(401);
                    },
                    withUndefined: function() {
                        expect(challenge).to.be.undefined;
                        expect(status).to.be.undefined;
                    },
                },
            }
        }

        describe('without challenges', function() {

            var handlers = genHandlers({});

            before(handlers.before);

            it('should not call verify', handlers.itDoesNotVerify);

            it('should fail without challenge and status', handlers.itFails.withUndefined);

        });

        describe('with challenges', function() {

            describe('default invalidToken challenge', function() {

                var handlers = genHandlers({
                    expectedChallenge: 'Bearer error="invalid_token" error_description="jwt expired"',
                    challenges: true,
                });

                before(handlers.before);

                it('should not call verify', handlers.itDoesNotVerify);

                it('should fail with challenge and status', handlers.itFails.withChallenge);

            });

            describe('custom invalidToken challenge', function() {

                var handlers = genHandlers({
                    expectedChallenge: 'custom challenge',
                    challenges: {
                        invalidToken: function(r) {
                            return 'custom challenge';
                        },
                    },
                });

                before(handlers.before);

                it('should not call verify', handlers.itDoesNotVerify);

                it('should fail with challenge and status', handlers.itFails.withChallenge);

            });

        });

    });

});
