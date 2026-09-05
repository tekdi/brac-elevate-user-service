// Dedicated Jest config for the searchUsersWithOrganization regression tests.
// The repo-root src/jest.config.js uses the @shelf/jest-mongodb preset (a leftover
// from the pre-Postgres version of this service) and only maps a handful of the
// module aliases actually declared in package.json's _moduleAliases — requiring
// users.js pulls in @utils and @dtos, neither of which that config maps. This
// config mirrors the FULL alias table against the real (Postgres) database
// instead, with no Mongo preset involved.
module.exports = {
	rootDir: '../../../',
	roots: ['<rootDir>/'],
	testMatch: ['<rootDir>/database/queries/__tests__/**/*.spec.js'],
	moduleNameMapper: {
		'@root/(.*)': '<rootDir>/$1',
		'@configs/(.*)': '<rootDir>/configs/$1',
		'@constants/(.*)': '<rootDir>/constants/$1',
		'@controllers/(.*)': '<rootDir>/controllers/$1',
		'@db/(.*)': '<rootDir>/db/$1',
		'@generics/(.*)': '<rootDir>/generics/$1',
		'@health-checks/(.*)': '<rootDir>/health-checks/$1',
		'@middlewares/(.*)': '<rootDir>/middlewares/$1',
		'@public/(.*)': '<rootDir>/public/$1',
		'@routes/(.*)': '<rootDir>/routes/$1',
		'@services/(.*)': '<rootDir>/services/$1',
		'@validators/(.*)': '<rootDir>/validators/$1',
		'@database/(.*)': '<rootDir>/database/$1',
		'@utils/(.*)': '<rootDir>/utils/$1',
		'@helpers/(.*)': '<rootDir>/helpers/$1',
		'@scripts/(.*)': '<rootDir>/scripts/$1',
		'@dtos/(.*)': '<rootDir>/dtos/$1',
	},
	testEnvironment: 'node',
	testTimeout: 30000,
}
