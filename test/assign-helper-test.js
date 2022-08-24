var assign = require('../lib/helpers/assign');

describe('lib/helpers/assign', function() {

	it('should make a shallow copy of objects', function() {
		var x = {};
		var obj = assign({foo:1}, {bar:2}, null, {baz:x});
		expect(obj).to.deep.equal({foo:1,bar:2,baz:{}});
		expect(obj).to.have.property('baz', x);
	});

	it('should only copy own properties', function() {
		var x = Object.create({bar:2});
		x.foo = 1;
		expect(assign({}, x)).to.not.have.property('bar');
	});

	it('should throw a type error when the first argument is null or undefined', function() {
		expect(function () {
			assign(null, {});
		}).to.throw(TypeError, 'Cannot convert undefined or null to object');
	});

});
