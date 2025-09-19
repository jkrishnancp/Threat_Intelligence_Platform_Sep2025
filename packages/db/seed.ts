import { PrismaClient, Role, DataSourceKind } from '@prisma/client'

const prisma = new PrismaClient()

async function main() {
  console.log('🌱 Seeding database...')

  // Create default organization
  const org = await prisma.org.create({
    data: {
      name: 'Default Organization',
    },
  })

  // Create admin user
  const adminUser = await prisma.user.create({
    data: {
      email: 'admin@example.com',
      name: 'Admin User',
      emailVerified: new Date(),
    },
  })

  // Link user to org as owner
  await prisma.userOrg.create({
    data: {
      userId: adminUser.id,
      orgId: org.id,
      role: Role.OWNER,
    },
  })

  // Create default data sources
  const dataSources = [
    { kind: DataSourceKind.NVD, label: 'National Vulnerability Database' },
    { kind: DataSourceKind.OSV, label: 'OSV.dev Vulnerabilities' },
    { kind: DataSourceKind.GHSA, label: 'GitHub Security Advisories' },
    { kind: DataSourceKind.CISA_KEV, label: 'CISA Known Exploited Vulnerabilities' },
  ]

  for (const source of dataSources) {
    await prisma.dataSource.create({
      data: {
        orgId: org.id,
        kind: source.kind,
        label: source.label,
        enabled: true,
      },
    })
  }

  // Create sample RSS data source
  await prisma.dataSource.create({
    data: {
      orgId: org.id,
      kind: DataSourceKind.RSS,
      label: 'CISA Current Activity',
      enabled: true,
      configJson: {
        url: 'https://www.cisa.gov/news.xml',
      },
    },
  })

  console.log('✅ Seeding completed!')
  console.log(`📧 Admin login: ${adminUser.email}`)
  console.log(`🏢 Organization: ${org.name}`)
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })