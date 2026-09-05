/**
 * Regression coverage for the account/search 500:
 *   SequelizeDatabaseError: column user_organizations.organization_id does not exist
 *
 * Root cause: searchUsersWithOrganization (database/queries/users.js) filtered
 * `organization_id` directly on the user_organizations join table, which has no
 * such column (it only has organization_code). The fix moves that numeric filter
 * onto the joined Organization row's own primary key and adds subQuery: false to
 * avoid a Sequelize count/subquery interaction between the two required nested
 * includes (organization, roles).
 *
 * These tests exercise the real function against the real (Postgres) database —
 * no mocking of Sequelize — using disposable fixtures created in beforeAll and
 * hard-deleted in afterAll. They do not touch any tenant/org/user created by
 * manual regression testing (fargo / fargo_org / users 74-77).
 */
const database = require('@database/models/index')
const { searchUsersWithOrganization } = require('@database/queries/users')

const RUN_ID = Date.now()
const TENANT_ONE = `search_fix_t1_${RUN_ID}`
const TENANT_TWO = `search_fix_t2_${RUN_ID}`

let orgA // tenant one, org A
let orgB // tenant one, org B
let orgC // tenant two, org C
let userInOrgA // tenant one, member of org A only
let userInOrgB // tenant one, member of org B only
let userInOtherTenant // tenant two, member of org C

async function createTenant(code) {
	return database.Tenant.create({
		code,
		name: code,
		status: 'ACTIVE',
		logo: 'none',
		created_at: new Date(),
		updated_at: new Date(),
	})
}

async function createOrganization(tenantCode, code) {
	return database.Organization.create({
		name: code,
		code,
		description: 'regression fixture',
		status: 'ACTIVE',
		tenant_code: tenantCode,
	})
}

async function createUser(tenantCode, name) {
	return database.User.create({
		tenant_code: tenantCode,
		name,
		password: 'not-a-real-hash',
		roles: [],
		status: 'ACTIVE',
	})
}

async function linkUserToOrganization(user, organization, tenantCode) {
	return database.UserOrganization.create({
		user_id: user.id,
		organization_code: organization.code,
		tenant_code: tenantCode,
	})
}

beforeAll(async () => {
	await createTenant(TENANT_ONE)
	await createTenant(TENANT_TWO)

	orgA = await createOrganization(TENANT_ONE, `${TENANT_ONE}_org_a`)
	orgB = await createOrganization(TENANT_ONE, `${TENANT_ONE}_org_b`)
	orgC = await createOrganization(TENANT_TWO, `${TENANT_TWO}_org_c`)

	userInOrgA = await createUser(TENANT_ONE, 'User In Org A')
	userInOrgB = await createUser(TENANT_ONE, 'User In Org B')
	userInOtherTenant = await createUser(TENANT_TWO, 'User In Other Tenant')

	await linkUserToOrganization(userInOrgA, orgA, TENANT_ONE)
	await linkUserToOrganization(userInOrgB, orgB, TENANT_ONE)
	await linkUserToOrganization(userInOtherTenant, orgC, TENANT_TWO)
})

afterAll(async () => {
	await database.UserOrganization.destroy({ where: { tenant_code: [TENANT_ONE, TENANT_TWO] }, force: true })
	await database.User.destroy({ where: { tenant_code: [TENANT_ONE, TENANT_TWO] }, force: true })
	await database.Organization.destroy({ where: { tenant_code: [TENANT_ONE, TENANT_TWO] }, force: true })
	await database.Tenant.destroy({ where: { code: [TENANT_ONE, TENANT_TWO] }, force: true })
	await database.sequelize.close()
})

describe('searchUsersWithOrganization — organization_id filter', () => {
	it('does not throw and returns the user when organization_id matches the correct tenant + organization', async () => {
		const result = await searchUsersWithOrganization({
			roleIds: [],
			organization_id: orgA.id,
			page: 1,
			limit: 10,
			tenantCode: TENANT_ONE,
			userIds: [userInOrgA.id],
		})

		expect(result.count).toBe(1)
		expect(result.data.map((u) => u.id)).toEqual([userInOrgA.id])
	})

	it('excludes a user who belongs to the tenant but a DIFFERENT organization', async () => {
		const result = await searchUsersWithOrganization({
			roleIds: [],
			organization_id: orgA.id,
			page: 1,
			limit: 10,
			tenantCode: TENANT_ONE,
			userIds: [userInOrgA.id, userInOrgB.id],
		})

		expect(result.count).toBe(1)
		expect(result.data.map((u) => u.id)).toEqual([userInOrgA.id])
	})

	it('excludes a user from a DIFFERENT tenant even when explicitly requested by id', async () => {
		const result = await searchUsersWithOrganization({
			roleIds: [],
			organization_id: orgA.id,
			page: 1,
			limit: 10,
			tenantCode: TENANT_ONE,
			userIds: [userInOrgA.id, userInOtherTenant.id],
		})

		expect(result.count).toBe(1)
		expect(result.data.map((u) => u.id)).toEqual([userInOrgA.id])
	})

	it('preserves prior behaviour when organization_id is omitted (no organization filter)', async () => {
		const result = await searchUsersWithOrganization({
			roleIds: [],
			organization_id: undefined,
			page: 1,
			limit: 10,
			tenantCode: TENANT_ONE,
			userIds: [userInOrgA.id, userInOrgB.id],
		})

		expect(result.count).toBe(2)
		expect(result.data.map((u) => u.id).sort()).toEqual([userInOrgA.id, userInOrgB.id].sort())
	})

	it('never raises SequelizeDatabaseError for the previously-broken organization_id path', async () => {
		await expect(
			searchUsersWithOrganization({
				roleIds: [],
				organization_id: orgA.id,
				page: 1,
				limit: 10,
				tenantCode: TENANT_ONE,
				userIds: [userInOrgA.id],
			})
		).resolves.toBeDefined()
	})
})
