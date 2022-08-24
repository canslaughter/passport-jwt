var verifyJwt = require('../lib/verify_jwt')
	, jwt = require('jsonwebtoken');

describe('lib/verify_jwt', function() {

	it('should run', function() {
		verifyJwt(jwt.sign({foo:'bar'}, 'secret'), 'secret');
	});

});
